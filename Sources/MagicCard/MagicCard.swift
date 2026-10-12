import Foundation
import Combine

// MARK: - Magic Card (UID Writable Card) Support
// Magic cards (also called Chinese magic cards) are special MIFARE Classic
// clones that allow writing the UID and Block 0.
//
// Types:
// - CUID: Can change UID, Gen 1 (most common)
// - CUID Gen 2: Improved version of Gen 1
// - FUID: Can only write UID once (fuses after write)
// - UFUID: Starts as UID-writable, can be fused to becomme normal card
// - Super CUID: Can change UID even after fusing
@MainActor
class MagicCardController: ObservableObject {
    @Published var statusMessage = ""
    @Published var isOperating = false
    
    private let bleManager: BLEManager
    
    init(bleManager: BLEManager) {
        self.bleManager = bleManager
    }
    
    // MARK: - Detection
    
    /// Detect if current card is a magic card
    /// Magic UIDs typically start with 0x08, 0x09, or 0x88
    func detectMagicCard(uid: [UInt8]) -> MagicCardType {
        guard uid.count >= 1 else { return .unknown }
        
        switch uid[0] {
        case 0x08: return .cuid
        case 0x09: return .fuid
        case 0x88: return .ufuid
        default:
            // Try to detect by special behavior
            return .normal
        }
    }
    
    enum MagicCardType: String, CaseIterable {
        case cuid = "CUID (可改UID)"
        case cuidGen2 = "CUID Gen2"
        case fuid = "FUID (一次性)"
        case ufuid = "UFUID (可融合)"
        case superCuid = "Super CUID"
        case normal = "普通卡片"
        case unknown = "未知"
    }
    
    // MARK: - Magic Card Commands
    
    /// Write UID to a magic card
    /// Magic card UID write sequence:
    /// 1. Halt card
    /// 2. Send special 7-bit write command
    /// 3. Card acknowledges with 0x0A
    /// 4. Send new UID (4 or 7 bytes)
    /// 5. Card acknowledges
    /// 6. Deselect and re-select card
    func writeUID(newUID: [UInt8]) async throws -> Bool {
        isOperating = true
        statusMessage = "写入 UID: \(newUID.map { String(format: "%02X", $0) }.joined(separator: ":"))..."
        
        guard newUID.count == 4 || newUID.count == 7 else {
            statusMessage = "UID 长度错误: 需要4或7字节"
            isOperating = false
            return false
        }
        
        // Step 1: Halt the card via InCommunicateThru
        let haltFrame = PN532CommandBuilder.inCommunicateThru([0x50, 0x00, 0x00, 0x00])
        do {
            let _ = try await bleManager.sendFrame(haltFrame)
        } catch {
            // Halt may fail, continue anyway
        }
        
        try await Task.sleep(nanoseconds: 50_000_000) // 50ms
        
        // Step 2: Send magic write command (Gen 1 CUID)
        // The magic command varies by card type:
        // For CUID Gen 1: 0x43 (write block 0)
        // Also common: 0xA0, 0xA1, 0xA2...
        
        // Approach 1: Write Block 0 with magic sequence
        // Some magic cards accept writes to Block 0 directly
        let block0Data = newUID + [UInt8](repeating: 0x00, count: 12)
        
        let writeFrame = PN532CommandBuilder.inCommunicateThru(
            [0xA0, 0x00] + block0Data
        )
        
        do {
            let response = try await bleManager.sendFrame(writeFrame)
            if response.data.first == 0x00 {
                statusMessage = "UID 写入成功!"
                isOperating = false
                return true
            }
        } catch {
            // First method failed, try alternative
        }
        
        // Approach 2: Backdoor command for Gen 1 CUID
        // Command: 0x40 (write to magic block) + data
        let magicWriteFrame = PN532CommandBuilder.inCommunicateThru(
            [0x43] + [0x00] + block0Data
        )
        
        do {
            let response = try await bleManager.sendFrame(magicWriteFrame)
            if response.data.first == 0x0A || response.data.first == 0x00 {
                statusMessage = "UID 写入成功 (方法2)!"
                isOperating = false
                return true
            }
        } catch {
            statusMessage = "UID 写入失败: 所有方法均无效"
            isOperating = false
            return false
        }
        
        isOperating = false
        return false
    }
    
    /// Write complete Block 0 (including UID, SAK, ATQA)
    /// Write complete Block 0 (including UID, SAK, ATQA)
    /// This is the block that defines the card identity
    func writeBlock0(uid: [UInt8], sak: UInt8 = 0x08, atqa: UInt16 = 0x0004) async throws -> Bool {
        isOperating = true
        statusMessage = "写入 Block 0..."
        
        var block0 = [UInt8](repeating: 0x00, count: 16)
        
        // 4-byte UID vs 7-byte UID
        if uid.count == 4 {
            block0[0] = uid[0]
            block0[1] = uid[1]
            block0[2] = uid[2]
            block0[3] = uid[3]
            block0[4] = uid[0] ^ uid[1] ^ uid[2] ^ uid[3] // BCC
            block0[5] = sak
            block0[6] = UInt8(atqa & 0xFF)
            block0[7] = UInt8((atqa >> 8) & 0xFF)
            let defaultTail: [UInt8] = [0x08, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05]
            for i in 0..<8 { block0[8 + i] = defaultTail[i] }
        } else {
            for i in 0..<min(uid.count, 7) { block0[i] = uid[i] }
            block0[7] = uid.prefix(7).reduce(0, ^)
            block0[8] = sak
            block0[9] = UInt8(atqa & 0xFF)
            block0[10] = UInt8((atqa >> 8) & 0xFF)
        }
        
        // Method 1: CUID (Gen 2) - Standard MIFARE auth with default keys then write block 0
        let defaultKeys: [[UInt8]] = [[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]]
        for key in defaultKeys {
            let authFrame = PN532CommandBuilder.mifareAuthenticate(
                target: 0x01,
                keyType: 0x60,
                block: 0,
                key: key,
                uid: Array(uid.prefix(4))
            )
            if let resp = try? await bleManager.sendFrame(authFrame, timeout: 0.8),
               PN532ResponseParser.parseDataExchange(resp.data).0 {
                let writeFrame = PN532CommandBuilder.mifareWriteBlock(target: 0x01, block: 0, data: block0)
                if let writeResp = try? await bleManager.sendFrame(writeFrame, timeout: 0.8),
                   PN532ResponseParser.parseDataExchange(writeResp.data).0 {
                    statusMessage = "Block 0 写入成功 (CUID Gen2)!"
                    isOperating = false
                    return true
                }
            } else {
                let listFrame = PN532Frame(tfi: .hostToPN532, data: [0x4A, 0x01, 0x00])
                _ = try? await bleManager.sendFrame(listFrame, timeout: 0.5)
            }
        }
        
        // Method 2: Gen 1 UID backdoor (InCommunicateThru A0)
        let writeFrame = PN532CommandBuilder.inCommunicateThru([0xA0, 0x00] + block0)
        if let response = try? await bleManager.sendFrame(writeFrame, timeout: 0.8),
           (response.data.first == 0x0A || response.data.first == 0x00) {
            statusMessage = "Block 0 写入成功 (UID 后门)!"
            isOperating = false
            return true
        }
        
        statusMessage = "Block 0 写入失败"
        isOperating = false
        return false
    }
    
    /// Fuse a UFUID card (make it permanent, no more UID changes)
    func fuseCard() async throws -> Bool {
        isOperating = true
        statusMessage = "融合卡片 (永久化)..."
        
        // UFUID fuse command: 0xC1
        let fuseFrame = PN532CommandBuilder.inCommunicateThru([0xC1, 0x00])
        
        do {
            let response = try await bleManager.sendFrame(fuseFrame)
            if response.data.first == 0x0A || response.data.first == 0x00 {
                statusMessage = "卡片融合成功，现在为永久卡片"
                isOperating = false
                return true
            }
        } catch {
            statusMessage = "卡片融合失败"
            isOperating = false
            return false
        }
        
        isOperating = false
        return false
    }
    
    /// Restore card to factory default (some magic cards support this)
    func restoreDefaults() async throws -> Bool {
        isOperating = true
        statusMessage = "恢复出厂设置..."
        
        // Some Gen 1 CUID cards support: 0xC0 (restore to factory)
        let restoreFrame = PN532CommandBuilder.inCommunicateThru([0xC0, 0x00])
        
        do {
            let response = try await bleManager.sendFrame(restoreFrame)
            if response.data.first == 0x0A || response.data.first == 0x00 {
                statusMessage = "卡片已恢复出厂设置"
                isOperating = false
                return true
            }
        } catch {
            statusMessage = "恢复失败"
            isOperating = false
            return false
        }
        
        isOperating = false
        return false
    }
    
    /// Clone a card: read source, write to magic card
    func cloneCard(sourceDump: MIFAREDump, targetUID: [UInt8]? = nil) async throws -> Bool {
        isOperating = true
        statusMessage = "开始克隆卡片..."
        
        // Step 1: Write Block 0 (UID + SAK + ATQA)
        let uid = targetUID ?? sourceDump.uid
        let success1 = try await writeBlock0(uid: uid, sak: sourceDump.sak)
        guard success1 else {
            statusMessage = "克隆失败: 无法写入 Block 0"
            isOperating = false
            return false
        }
        
        // Step 2: Re-select card after UID change
        try await Task.sleep(nanoseconds: 200_000_000) // 200ms
        _ = try? await bleManager.sendFrame(
            PN532CommandBuilder.listPassiveTarget(maxTargets: 1, baudRate: 0x00)
        )
        
        // Step 3: Write each sector's data
        let sortedSectors = sourceDump.sectors.sorted { $0.key < $1.key }
        for (sector, data) in sortedSectors {
            await MainActor.run {
                statusMessage = "克隆: 写入扇区 \(sector)..."
            }
            
            // Need key to write - try default keys
            let startBlock = sector < 32 ? sector * 4 : 128 + (sector - 32) * 16
            let trailerBlock = startBlock + (sector < 32 ? 3 : 15)
            
            // Try key A first (factory default), then sourceDump known key if available
            let cleanUid = Array(uid.prefix(4))
            var writeKeys: [[UInt8]] = [[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]]
            if let known = sourceDump.knownKeys[sector] {
                writeKeys.append(known.keyData)
            }
            
            var sectorAuthSuccess = false
            for k in writeKeys {
                let authFrame = PN532CommandBuilder.mifareAuthenticate(
                    target: 0x01,
                    keyType: 0x60,
                    block: UInt8(trailerBlock),
                    key: k,
                    uid: cleanUid
                )
                if let authResp = try? await bleManager.sendFrame(authFrame, timeout: 0.8),
                   PN532ResponseParser.parseDataExchange(authResp.data).0 {
                    sectorAuthSuccess = true
                    break
                } else {
                    let listFrame = PN532Frame(tfi: .hostToPN532, data: [0x4A, 0x01, 0x00])
                    _ = try? await bleManager.sendFrame(listFrame, timeout: 0.5)
                }
            }
            
            if sectorAuthSuccess {
                let blockCount = sector < 32 ? 4 : 16
                for b in 0..<blockCount {
                    let blockData = Array(data[b * 16..<min((b + 1) * 16, data.count)])
                    if blockData.count == 16 {
                        let writeFrame = PN532CommandBuilder.mifareWriteBlock(
                            target: 0x01,
                            block: UInt8(startBlock + b),
                            data: blockData
                        )
                        _ = try? await bleManager.sendFrame(writeFrame, timeout: 0.8)
                    }
                }
            } else {
                statusMessage = "克隆: 扇区 \(sector) 跳过 (认证失败)"
            }
        }
        
        statusMessage = "克隆完成!"
        isOperating = false
        return true
    }
    
    // MARK: - Utility
    
    /// Validate UID format (hex string)
    static func validateUID(_ uidString: String) -> Bool {
        let hex = uidString.replacingOccurrences(of: " ", with: "").replacingOccurrences(of: ":", with: "")
        guard hex.count == 8 || hex.count == 14 else { return false }
        return hex.rangeOfCharacter(from: CharacterSet(charactersIn: "0123456789ABCDEFabcdef").inverted) == nil
    }
    
    /// Parse UID from hex string
    static func parseUID(_ uidString: String) -> [UInt8] {
        let hex = uidString.replacingOccurrences(of: " ", with: "").replacingOccurrences(of: ":", with: "")
        var uid = [UInt8]()
        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            if let byte = UInt8(hex[index..<nextIndex], radix: 16) {
                uid.append(byte)
            }
            index = nextIndex
        }
        return uid
    }
}