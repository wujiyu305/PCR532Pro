import Foundation
import Combine

// MARK: - MIFARE Access Bits Parser
struct AccessBitsInfo {
    let isValid: Bool
    let dataBlockPermissions: [String] // permissions for block 0, 1, 2
    let trailerPermission: String     // permission for trailer block
    let rawBytes: [UInt8]
}

struct AccessBitsParser {
    static func parse(_ trailer: [UInt8]) -> AccessBitsInfo {
        guard trailer.count == 16 else {
            return AccessBitsInfo(isValid: false, dataBlockPermissions: [], trailerPermission: "未知", rawBytes: [])
        }
        let ab = Array(trailer[6..<10])
        let b6 = ab[0], b7 = ab[1], b8 = ab[2]
        
        // Invert check
        let c1 = ((b7 >> 4) & 0x0F)
        let c1_inv = (b6 & 0x0F)
        let c2 = (b8 & 0x0F)
        let c2_inv = ((b6 >> 4) & 0x0F)
        let c3 = ((b8 >> 4) & 0x0F)
        let c3_inv = (b7 & 0x0F)
        
        let valid = (c1 ^ c1_inv == 0x0F) && (c2 ^ c2_inv == 0x0F) && (c3 ^ c3_inv == 0x0F)
        
        var blockPerms: [String] = []
        for i in 0..<3 {
            let bitC1 = (c1 >> i) & 1
            let bitC2 = (c2 >> i) & 1
            let bitC3 = (c3 >> i) & 1
            let mode = (bitC1 << 2) | (bitC2 << 1) | bitC3
            
            switch mode {
            case 0b000: blockPerms.append("读: A|B, 写: A|B (常规)")
            case 0b010: blockPerms.append("读: A|B, 写: 禁用 (只读)")
            case 0b100: blockPerms.append("读: A|B, 写: B (普通受限)")
            case 0b110: blockPerms.append("读: A|B, 写: B, 增减: A|B (电子钱包)")
            case 0b001: blockPerms.append("读: A|B, 写: 禁用, 增减: A|B (只减块)")
            case 0b011: blockPerms.append("读: B, 写: B (B专属)")
            case 0b101: blockPerms.append("读: B, 写: 禁用 (B只读)")
            default: blockPerms.append("禁用 (全部锁死)")
            }
        }
        
        let tC1 = (c1 >> 3) & 1
        let tC2 = (c2 >> 3) & 1
        let tC3 = (c3 >> 3) & 1
        let tMode = (tC1 << 2) | (tC2 << 1) | tC3
        
        let trailerDesc: String
        switch tMode {
        case 0b000: trailerDesc = "KeyA写: A, 控制位: A|A, KeyB写: A (出厂默认)"
        case 0b010: trailerDesc = "KeyA写: 禁用, 控制位: A|禁用, KeyB写: 禁用"
        case 0b100: trailerDesc = "KeyA写: B, 控制位: A|B, KeyB写: B"
        case 0b110: trailerDesc = "KeyA写: 禁用, 控制位: A|B, KeyB写: 禁用"
        case 0b001: trailerDesc = "KeyA写: A, 控制位: A|A, KeyB读写: A|A"
        case 0b011: trailerDesc = "KeyA写: B, 控制位: A|B, KeyB读写: B|B"
        case 0b101: trailerDesc = "KeyA写: 禁用, 控制位: A|B, KeyB读写: B|禁用"
        default: trailerDesc = "控制位保护/锁死"
        }
        
        return AccessBitsInfo(isValid: valid, dataBlockPermissions: blockPerms, trailerPermission: trailerDesc, rawBytes: ab)
    }
}

// MARK: - MIFARE Sector & Block
struct MIFAREBlock: Identifiable, Equatable, CustomStringConvertible {
    let id = UUID()
    let number: UInt8
    var data: [UInt8]  // 16 bytes
    var isSectorTrailer: Bool {
        if number < 128 {
            return (number + 1) % 4 == 0
        } else {
            return (number - 128 + 1) % 16 == 0
        }
    }
    var isValueBlock: Bool { !isSectorTrailer && number > 0 && number < 128 }
    
    var hexString: String {
        data.map { String(format: "%02X", $0) }.joined(separator: " ")
    }
    
    var description: String {
        "Block \(number): \(hexString)"
    }
    
    // Sector trailer parsing
    var keyA: [UInt8] {
        guard isSectorTrailer && data.count >= 16 else { return [UInt8](repeating: 0, count: 6) }
        return Array(data[0..<6])
    }
    
    var accessBits: [UInt8] {
        guard isSectorTrailer && data.count >= 16 else { return [UInt8](repeating: 0, count: 4) }
        return Array(data[6..<10])
    }
    
    var keyB: [UInt8] {
        guard isSectorTrailer && data.count >= 16 else { return [UInt8](repeating: 0, count: 6) }
        return Array(data[10..<16])
    }
    
    var accessBitsDescription: String {
        guard isSectorTrailer && data.count >= 16 else { return "N/A" }
        let info = AccessBitsParser.parse(data)
        return info.trailerPermission
    }
}

struct MIFARESector: Identifiable {
    let id = UUID()
    let number: Int
    var blocks: [MIFAREBlock]
    
    var is4K: Bool { number >= 32 }
    var blockCount: Int { is4K ? 16 : 4 }
    var startBlock: Int {
        number < 32 ? number * 4 : 128 + (number - 32) * 16
    }
    
    var trailerBlock: MIFAREBlock? {
        blocks.last
    }
    
    var isAuthenticated: Bool = false
    var knownKeyType: UInt8? = nil // 0x60 = Key A, 0x61 = Key B
    var knownKey: [UInt8]? = nil
    
    var dataBlocks: [MIFAREBlock] {
        blocks.filter { !$0.isSectorTrailer }
    }
    
    var accessBitsInfo: AccessBitsInfo? {
        guard let trailer = trailerBlock, trailer.data.count >= 16 else { return nil }
        return AccessBitsParser.parse(trailer.data)
    }
}

// MARK: - MIFARE Key Manager
class MIFAREKeyManager {
    // Default keys known to work on most MIFARE Classic cards
    static let defaultKeys: [[UInt8]] = [
        [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], // Factory default
        [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5],
        [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],
        [0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD],
        [0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F],
        [0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7],
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0],
        [0xA1, 0xB1, 0xC1, 0xD1, 0xE1, 0xF1],
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
        [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC],
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        [0x00, 0x00, 0x00, 0x00, 0x00, 0xFF],
        [0x11, 0x11, 0x11, 0x11, 0x11, 0x11],
        [0x22, 0x22, 0x22, 0x22, 0x22, 0x22],
        [0x33, 0x33, 0x33, 0x33, 0x33, 0x33],
        [0x44, 0x44, 0x44, 0x44, 0x44, 0x44],
        [0x55, 0x55, 0x55, 0x55, 0x55, 0x55],
        [0x66, 0x66, 0x66, 0x66, 0x66, 0x66],
        [0x77, 0x77, 0x77, 0x77, 0x77, 0x77],
        [0x88, 0x88, 0x88, 0x88, 0x88, 0x88],
        [0x99, 0x99, 0x99, 0x99, 0x99, 0x99],
        [0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA],
        [0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB],
        [0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC],
        [0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD],
        [0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE],
        [0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56],
        [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB],
        [0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00],
        [0x70, 0x69, 0x73, 0x73, 0x65, 0x73], // "pisses" (another common test key)
        [0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54],
        [0x20, 0x21, 0x22, 0x23, 0x24, 0x25],
        [0x30, 0x31, 0x32, 0x33, 0x34, 0x35],
        [0x40, 0x41, 0x42, 0x43, 0x44, 0x45],
        [0x50, 0x51, 0x52, 0x53, 0x54, 0x55],
        [0x60, 0x61, 0x62, 0x63, 0x64, 0x65],
        [0x70, 0x71, 0x72, 0x73, 0x74, 0x75],
        [0x80, 0x81, 0x82, 0x83, 0x84, 0x85],
        [0x90, 0x91, 0x92, 0x93, 0x94, 0x95],
        [0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5],
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Duplicate, but keep for count
        [0x4E, 0x4E, 0x4E, 0x4E, 0x4E, 0x4E],
    ]
    
    static let defaultKeysDescription: [(String, [UInt8])] = [
        ("工厂默认", [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
        ("A0A1A2A3A4A5", [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5]),
        ("B0B1B2B3B4B5", [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5]),
        ("4D3A99C351DD", [0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD]),
        ("全零", [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        ("全A", [0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]),
        ("全B", [0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB]),
    ]
}

// MARK: - MIFARE Card Dump
struct MIFAREDump: Identifiable, Codable {
    var id: UUID = UUID()
    var name: String
    var date: Date
    var uid: [UInt8]
    var sak: UInt8
    var atqaValue: UInt16
    var sectors: [Int: [UInt8]]
    struct KnownKeyEntry: Codable {
        var keyData: [UInt8]
        var keyType: UInt8
    }
    var knownKeys: [Int: KnownKeyEntry]
    
    // Computed properties for backward compatibility
    var atqa: (UInt8, UInt8) {
        (UInt8((atqaValue >> 8) & 0xFF), UInt8(atqaValue & 0xFF))
    }
    
    var uidString: String {
        uid.map { String(format: "%02X", $0) }.joined(separator: ":")
    }
    
    var formattedDate: String {
        let df = DateFormatter()
        df.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return df.string(from: date)
    }
    
    var sectorCount: Int {
        sectors.count
    }
    
    /// Convert dump to binary data for export
    func toBinary() -> Data {
        var data = Data()
        data.append(contentsOf: uid)
        data.append(sak)
        data.append(atqa.0)
        data.append(atqa.1)
        
        let sortedSectors = sectors.sorted { $0.key < $1.key }
        for (_, sectorData) in sortedSectors {
            data.append(contentsOf: sectorData)
        }
        return data
    }
    
    /// Load dump from binary data
    static func fromBinary(_ data: Data, name: String) -> MIFAREDump? {
        guard data.count >= 7 else { return nil }
        // Actually UID can be 4 or 7 bytes... simplified
        let _uid = [UInt8](data[0..<4])
        let sak = data[4]
        let atqaValue = (UInt16(data[5]) << 8) | UInt16(data[6])
        var offset = 7
        
        var sectors = [Int: [UInt8]]()
        var sectorNum = 0
        while offset < data.count {
            let sectorSize = sectorNum < 32 ? 64 : 256
            guard offset + sectorSize <= data.count else { break }
            sectors[sectorNum] = [UInt8](data[offset..<offset + sectorSize])
            offset += sectorSize
            sectorNum += 1
        }
        
        return MIFAREDump(name: name, date: Date(), uid: _uid, sak: sak, atqaValue: atqaValue, sectors: sectors, knownKeys: [:])
    }
}

// MARK: - MIFARE Card Controller
// This is the main class that handles all MIFARE operations via PN532
@MainActor
class MIFAREController: ObservableObject {
    @Published var currentCard: CardInfo?
    @Published var sectors = [MIFARESector]()
    @Published var isReading = false
    @Published var progress: Double = 0
    @Published var statusMessage = ""
    @Published var dumpHistory = [MIFAREDump]()
    @Published var specifiedKeyHex: String = "" // User-specified priority key (e.g. FFFFFFFFFFFF)
    
    private let bleManager: BLEManager
    private var keyManager = MIFAREKeyManager()
    var customKeys = [[UInt8]]()
    
    init(bleManager: BLEManager) {
        self.bleManager = bleManager
    }
    
    // MARK: - Card Detection
    
    /// Detect card and get UID/SAK/ATQA with robust polling window
    func detectCard() async throws -> CardInfo {
        statusMessage = "Detecting card..."
        
        // RFConfiguration MaxRetries: passive = 0x14 (20 attempts, ~300-400ms RF activation window)
        _ = try? await bleManager.sendFrame(
            PN532Frame(tfi: .hostToPN532, data: [0x32, 0x05, 0xFF, 0x01, 0x14]),
            timeout: 1.0
        )
        
        // InListPassiveTarget: max 1, 106kbps type A
        let listFrame = PN532Frame(tfi: .hostToPN532, data: [0x4A, 0x01, 0x00])
        let deadline = Date().addingTimeInterval(2.5)
        
        while Date() < deadline {
            do {
                let response = try await bleManager.sendFrame(listFrame, timeout: 1.5)
                let cards = PN532ResponseParser.parseTargetList(response.data)
                if let card = cards.first {
                    currentCard = card
                    statusMessage = "Found: \(card.typeDescription) UID \(card.uidString)"
                    return card
                }
            } catch {
                // If single poll times out or returns no card, continue loop
            }
            try await Task.sleep(nanoseconds: 50_000_000) // 50ms pause between attempts
        }
        
        statusMessage = "No card detected"
        throw PN532Error.noCardPresent
    }
    
    func detectCardDirect() async throws -> CardInfo {
        try await detectCard()
    }
    
    /// Re-activate card to exit HALT state after a failed authentication
    func reselectCard() async throws {
        let listFrame = PN532Frame(tfi: .hostToPN532, data: [0x4A, 0x01, 0x00])
        _ = try? await bleManager.sendFrame(listFrame, timeout: 0.6)
    }
    
    // MARK: - Authentication
    
    /// Authenticate with a sector/block using given key
    func authenticate(sector: Int, block: UInt8, key: [UInt8], keyType: UInt8) async throws -> Bool {
        let uid = currentCard?.uid ?? [0x00, 0x00, 0x00, 0x00]
        let authFrame = PN532CommandBuilder.mifareAuthenticate(
            target: 0x01,
            keyType: keyType,
            block: block,
            key: key,
            uid: uid
        )
        
        do {
            let response = try await bleManager.sendFrame(authFrame, timeout: 0.8)
            let (success, _) = PN532ResponseParser.parseDataExchange(response.data)
            
            if success {
                if sector < sectors.count {
                    sectors[sector].isAuthenticated = true
                    sectors[sector].knownKey = key
                    sectors[sector].knownKeyType = keyType
                }
                return true
            }
        } catch {
            // Auth packet timeout or comm error
        }
        
        // When auth fails, MIFARE card enters HALT state. Reselect card to allow subsequent auth attempts.
        _ = try? await reselectCard()
        return false
    }
    
    /// Try to authenticate with known keys (dictionary attack for a single sector)
    func tryDefaultKeys(sector: Int, block: UInt8) async throws -> (Bool, [UInt8], UInt8) {
        var allKeys = MIFAREKeyManager.defaultKeys + customKeys
        
        // Priority: if user specified a key, try it first
        let cleanedSpec = specifiedKeyHex.trimmingCharacters(in: .whitespacesAndNewlines)
        let specKey = HexUtils.hexToBytes(cleanedSpec)
        if specKey.count == 6 {
            allKeys.insert(specKey, at: 0)
        }
        
        // Try Key A first, then Key B
        for keyType: UInt8 in [0x60, 0x61] {
            for key in allKeys {
                let success = try await authenticate(sector: sector, block: block, key: key, keyType: keyType)
                if success {
                    let keyHex = key.map { String(format: "%02X", $0) }.joined()
                    statusMessage = "扇区 \(sector) 密钥已找到: \(keyHex) (\(keyType == 0x60 ? "A" : "B"))"
                    let cardUID = currentCard?.uidString ?? "卡片"
                    KeyStore.shared.saveKeyIfNotExists(
                        label: "\(cardUID)-S\(sector)-\(keyType == 0x60 ? "A" : "B")",
                        key: key
                    )
                    return (true, key, keyType)
                }
            }
        }
        
        return (false, [UInt8](repeating: 0, count: 6), 0)
    }
    
    // MARK: - Read Operations
    
    /// Read a single block
    func readBlock(block: UInt8) async throws -> [UInt8] {
        let readFrame = PN532CommandBuilder.mifareReadBlock(target: 0x01, block: block)
        let response = try await bleManager.sendFrame(readFrame)
        let (success, data) = PN532ResponseParser.parseDataExchange(response.data)
        
        guard success, data.count >= 16 else {
            throw PN532Error.communicationError("读块失败 Block \(block)")
        }
        
        return Array(data[0..<16])
    }
    
    /// Read a sector (all blocks)
    func readSector(sectorNum: Int, key: [UInt8], keyType: UInt8) async throws -> MIFARESector {
        let is4K = sectorNum >= 32
        let blockCount = is4K ? 16 : 4
        let startBlock = sectorNum < 32 ? sectorNum * 4 : 128 + (sectorNum - 32) * 16
        
        var blocks = [MIFAREBlock]()
        
        // Authenticate with the sector trailer block
        let trailerBlock = UInt8(startBlock + blockCount - 1)
        let authSuccess = try await authenticate(sector: sectorNum, block: trailerBlock, key: key, keyType: keyType)
        
        guard authSuccess else {
            throw PN532Error.authFailed
        }
        
        // Read all blocks in the sector
        for i in 0..<blockCount {
            let blockNum = UInt8(startBlock + i)
            let data = try await readBlock(block: blockNum)
            blocks.append(MIFAREBlock(number: blockNum, data: data))
            
            await MainActor.run {
                progress = Double(sectorNum * blockCount + i + 1) / Double(40 * 4)
            }
        }
        
        var result = MIFARESector(number: sectorNum, blocks: blocks)
        result.isAuthenticated = true
        result.knownKey = key
        result.knownKeyType = keyType
        
        return result
    }
    
    /// Read all sectors (full dump)
    func readAllSectors(progressCallback: ((Double) -> Void)? = nil) async throws -> [MIFARESector] {
        isReading = true
        progress = 0
        statusMessage = "开始全卡读取..."
        
        // Ensure card is active before starting
        _ = try? await reselectCard()
        
        var allSectors = [MIFARESector]()
        let totalSectors = currentCard?.totalSectors ?? 16
        var lastWorkingKey: [UInt8]? = nil
        var lastWorkingKeyType: UInt8 = 0x60
        
        for i in 0..<totalSectors {
            statusMessage = "读取扇区 \(i)/\(totalSectors - 1)..."
            progress = Double(i) / Double(totalSectors)
            
            let is4K = i >= 32
            let blockCount = is4K ? 16 : 4
            let startBlock = i < 32 ? i * 4 : 128 + (i - 32) * 16
            let trailerBlock = UInt8(startBlock + blockCount - 1)
            
            var sectorReadSuccess = false
            
            // Fast path: try last known working key first
            if let wKey = lastWorkingKey {
                if let sector = try? await readSector(sectorNum: i, key: wKey, keyType: lastWorkingKeyType) {
                    allSectors.append(sector)
                    sectorReadSuccess = true
                }
            }
            
            // If not successful, try default keys dictionary
            if !sectorReadSuccess {
                let (foundKey, sKey, sKeyType) = try await tryDefaultKeys(sector: i, block: trailerBlock)
                if foundKey {
                    lastWorkingKey = sKey
                    lastWorkingKeyType = sKeyType
                    if let sector = try? await readSector(sectorNum: i, key: sKey, keyType: sKeyType) {
                        allSectors.append(sector)
                        sectorReadSuccess = true
                    }
                }
            }
            
            // If still not readable, create empty placeholder sector
            if !sectorReadSuccess {
                var blocks = [MIFAREBlock]()
                for b in 0..<blockCount {
                    blocks.append(MIFAREBlock(number: UInt8(startBlock + b), data: [UInt8](repeating: 0x00, count: 16)))
                }
                var emptySector = MIFARESector(number: i, blocks: blocks)
                emptySector.isAuthenticated = false
                allSectors.append(emptySector)
                statusMessage = "扇区 \(i): 密钥未知，跳过"
            }
        }
        
        sectors = allSectors
        isReading = false
        progress = 1.0
        let decryptedCount = allSectors.filter { $0.isAuthenticated }.count
        statusMessage = "读取完成: \(decryptedCount)/\(totalSectors) 个扇区已解密"
        
        if decryptedCount == 0 {
            throw PN532Error.authFailed
        }
        
        return allSectors
    }
    
    // MARK: - Write Operations
    
    /// Write a single block
    func writeBlock(block: UInt8, data: [UInt8]) async throws -> Bool {
        guard data.count == 16 else {
            throw PN532Error.communicationError("写入数据必须为16字节")
        }
        
        let writeFrame = PN532CommandBuilder.mifareWriteBlock(target: 0x01, block: block, data: data)
        let response = try await bleManager.sendFrame(writeFrame)
        let (success, _) = PN532ResponseParser.parseDataExchange(response.data)
        return success
    }
    
    /// Write a sector (all data blocks + trailer)
    func writeSector(_ sector: MIFARESector) async throws -> Bool {
        guard let key = sector.knownKey, let keyType = sector.knownKeyType else {
            throw PN532Error.authFailed
        }
        
        let trailerBlock = sector.blocks.last!
        let authSuccess = try await authenticate(sector: sector.number, block: trailerBlock.number, key: key, keyType: keyType)
        guard authSuccess else { throw PN532Error.authFailed }
        
        for block in sector.blocks {
            if !block.isSectorTrailer || block == sector.blocks.last {
                let success = try await writeBlock(block: block.number, data: block.data)
                guard success else { return false }
            }
        }
        
        return true
    }
    
    // MARK: - Dump Management
    
    /// Save current dump to local storage
    func saveCurrentDump(name: String) -> Bool {
        guard let card = currentCard else { return false }
        
        var sectorData = [Int: [UInt8]]()
        var knownKeys = [Int: MIFAREDump.KnownKeyEntry]()
        
        for sector in sectors {
            var fullData = [UInt8]()
            for block in sector.blocks {
                fullData.append(contentsOf: block.data)
            }
            sectorData[sector.number] = fullData
            if let key = sector.knownKey, let keyType = sector.knownKeyType {
                knownKeys[sector.number] = MIFAREDump.KnownKeyEntry(keyData: key, keyType: keyType)
            }
        }
        
        let atqaValue = (UInt16(card.atqa.0) << 8) | UInt16(card.atqa.1)
        let dump = MIFAREDump(
            name: name,
            date: Date(),
            uid: card.uid,
            sak: card.sak,
            atqaValue: atqaValue,
            sectors: sectorData,
            knownKeys: knownKeys
        )
        
        dumpHistory.append(dump)
        saveDumpsToDisk()
        return true
    }
    
    /// Extract dump to binary for export
    func exportDumpToBinary(_ dump: MIFAREDump) -> Data {
        return dump.toBinary()
    }
    
    /// Import dump from binary data
    func importDumpFromBinary(_ data: Data, name: String) -> MIFAREDump? {
        return MIFAREDump.fromBinary(data, name: name)
    }
    
    // MARK: - Persistence
    
    private func dumpsFilePath() -> URL {
        let paths = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)
        return paths[0].appendingPathComponent("pcr532_dumps.json")
    }
    
    func loadDumpsFromDisk() {
        let url = dumpsFilePath()
        guard let data = try? Data(contentsOf: url),
              let dumps = try? JSONDecoder().decode([MIFAREDump].self, from: data) else {
            return
        }
        dumpHistory = dumps
    }
    
    func saveDumpsToDisk() {
        let url = dumpsFilePath()
        guard let data = try? JSONEncoder().encode(dumpHistory) else { return }
        try? data.write(to: url)
    }
    
    // MARK: - Advanced Card Operations
    
    /// Read a specific block with a custom key
    func readBlockWithKey(block: UInt8, key: [UInt8], keyType: UInt8 = 0x60) async throws -> [UInt8] {
        let sectorNum = block < 128 ? Int(block / 4) : 32 + Int((block - 128) / 16)
        let authSuccess = try await authenticate(sector: sectorNum, block: block, key: key, keyType: keyType)
        guard authSuccess else {
            HapticFeedback.error()
            throw PN532Error.authFailed
        }
        let data = try await readBlock(block: block)
        HapticFeedback.success()
        return data
    }
    
    /// Write a specific block with a custom key
    func writeBlockWithKey(block: UInt8, data: [UInt8], key: [UInt8], keyType: UInt8 = 0x60) async throws -> Bool {
        guard data.count == 16 else {
            HapticFeedback.error()
            throw PN532Error.communicationError("数据必须为 16 字节")
        }
        let sectorNum = block < 128 ? Int(block / 4) : 32 + Int((block - 128) / 16)
        let authSuccess = try await authenticate(sector: sectorNum, block: block, key: key, keyType: keyType)
        guard authSuccess else {
            HapticFeedback.error()
            throw PN532Error.authFailed
        }
        let success = try await writeBlock(block: block, data: data)
        if success {
            HapticFeedback.success()
        } else {
            HapticFeedback.error()
        }
        return success
    }
    
    /// Write a full dump back to the currently attached card
    func writeDumpToCard(_ dump: MIFAREDump) async throws -> (written: Int, failed: Int) {
        isReading = true
        progress = 0
        statusMessage = "开始向卡片回写 Dump: \(dump.name)..."
        HapticFeedback.impact(.medium)
        
        // Ensure card active
        _ = try? await reselectCard()
        
        var writtenSectors = 0
        var failedSectors = 0
        let total = dump.sectors.count
        
        for (idx, item) in dump.sectors.sorted(by: { $0.key < $1.key }).enumerated() {
            let sectorNum = item.key
            let data = item.value
            progress = Double(idx) / Double(max(total, 1))
            statusMessage = "正在写入扇区 \(sectorNum)..."
            
            let is4K = sectorNum >= 32
            let blockCount = is4K ? 16 : 4
            let startBlock = sectorNum < 32 ? sectorNum * 4 : 128 + (sectorNum - 32) * 16
            let trailerBlock = UInt8(startBlock + blockCount - 1)
            
            var candidateKeys: [(key: [UInt8], type: UInt8)] = []
            if let entry = dump.knownKeys[sectorNum] {
                candidateKeys.append((entry.keyData, entry.keyType))
            }
            candidateKeys.append(([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], 0x60))
            candidateKeys.append(([0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 0x60))
            candidateKeys.append(([0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5], 0x60))
            
            var authed = false
            for k in candidateKeys {
                if try await authenticate(sector: sectorNum, block: trailerBlock, key: k.key, keyType: k.type) {
                    authed = true
                    break
                }
            }
            
            guard authed else {
                failedSectors += 1
                statusMessage = "扇区 \(sectorNum) 认证失败，跳过"
                continue
            }
            
            var sectorWriteFailed = false
            for b in 0..<blockCount {
                let currentBlock = UInt8(startBlock + b)
                // Block 0 on normal cards is read-only
                if currentBlock == 0 && !(currentCard?.isMagicCard ?? false) {
                    continue
                }
                let blockOffset = b * 16
                guard blockOffset + 16 <= data.count else { continue }
                let blockData = Array(data[blockOffset..<blockOffset + 16])
                
                let success = try await writeBlock(block: currentBlock, data: blockData)
                if !success {
                    sectorWriteFailed = true
                    break
                }
            }
            
            if sectorWriteFailed {
                failedSectors += 1
            } else {
                writtenSectors += 1
            }
        }
        
        isReading = false
        progress = 1.0
        if failedSectors == 0 {
            HapticFeedback.success()
            statusMessage = "Dump 回写成功! 写入 \(writtenSectors) 个扇区"
        } else {
            HapticFeedback.warning()
            statusMessage = "Dump 回写完成: 成功 \(writtenSectors) 个, 失败 \(failedSectors) 个"
        }
        
        return (writtenSectors, failedSectors)
    }
    
    /// Save all discovered keys from currently read sectors to KeyStore
    @discardableResult
    func saveDiscoveredKeysToStore() -> Int {
        var keysToSave = [(String, [UInt8])]()
        let cardPrefix = currentCard?.uidString ?? "卡片"
        for sector in sectors where sector.isAuthenticated {
            if let key = sector.knownKey {
                let typeStr = (sector.knownKeyType == 0x61) ? "B" : "A"
                let label = "\(cardPrefix) 扇区\(sector.number)-\(typeStr)"
                keysToSave.append((label, key))
            }
        }
        let added = KeyStore.shared.saveMultipleKeys(keysToSave)
        if added > 0 {
            HapticFeedback.success()
            statusMessage = "已保存 \(added) 个新密钥到密钥库"
        } else {
            HapticFeedback.warning()
            statusMessage = "密钥已存在于密钥库中"
        }
        return added
    }
}