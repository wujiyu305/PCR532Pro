import Foundation

// MARK: - PN532 Error
enum PN532Error: LocalizedError {
    case invalidResponse
    case ackFailed
    case nackReceived
    case timeout
    case notConnected
    case noCardPresent
    case authFailed
    case invalidFrame
    case communicationError(String)
    case hardwareError(UInt8)
    case cardRemoved
    case unknownError
    
    var errorDescription: String? {
        switch self {
        case .invalidResponse: return "Invalid response"
        case .ackFailed: return "ACK failed"
        case .nackReceived: return "NACK"
        case .timeout: return "Communication timeout"
        case .notConnected: return "Device not connected"
        case .noCardPresent: return "No card detected"
        case .authFailed: return "Auth failed"
        case .invalidFrame: return "Invalid frame"
        case .communicationError(let s): return "Comm error: \(s)"
        case .hardwareError(let c): return "HW error: 0x\(String(format: "%02X", c))"
        case .cardRemoved: return "Card removed"
        case .unknownError: return "Unknown error"
        }
    }
}

// MARK: - PN532 Frame
struct PN532Frame {
    enum TFI: UInt8 {
        case hostToPN532 = 0xD4
        case pn532ToHost = 0xD5
    }
    
    static let ack: [UInt8] = [0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00]
    static let nack: [UInt8] = [0x00, 0x00, 0xFF, 0x01, 0xFE, 0x00]
    /// HSU wake-up: long preamble so PN532 exits low power
    static let wakeUp: [UInt8] = [
        0x55, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ]
    static let errorTFI: UInt8 = 0x7F
    
    let tfi: TFI
    let data: [UInt8]
    
    var isAckPlaceholder: Bool {
        tfi == .hostToPN532 && data.isEmpty
    }
    
    func encode() -> [UInt8] {
        var frame = [UInt8]()
        let payload = [tfi.rawValue] + data
        let len = payload.count
        
        if len > 254 {
            let extLen = UInt16(len)
            let sum = payload.reduce(0) { UInt16($0) + UInt16($1) }
            let dcs = UInt8((0x0100 - (sum & 0xFF)) & 0xFF)
            
            frame.append(contentsOf: [0x00, 0x00, 0xFF])
            frame.append(0xFF); frame.append(0xFF)
            frame.append(UInt8((extLen >> 8) & 0xFF))
            frame.append(UInt8(extLen & 0xFF))
            // Extended LCS: 0x10000 - extLen (two bytes, low 8 of each complement style)
            let lcs = UInt16(0) &- extLen  // two's complement of extLen in 16-bit
            frame.append(UInt8((lcs >> 8) & 0xFF))
            frame.append(UInt8(lcs & 0xFF))
            frame.append(contentsOf: payload)
            frame.append(dcs)
            frame.append(0x00)
        } else {
            let lcs = (0x0100 - UInt16(len)) & 0xFF
            let sum = payload.reduce(0) { $0 &+ $1 }
            let dcs = (0x0100 - UInt16(sum)) & 0xFF
            
            // Single preamble 0x00 is enough; many modules also accept 0x00 0x00 0xFF
            frame.append(contentsOf: [0x00, 0x00, 0xFF])
            frame.append(UInt8(len))
            frame.append(UInt8(lcs))
            frame.append(contentsOf: payload)
            frame.append(UInt8(dcs))
            frame.append(0x00)
        }
        
        return frame
    }
    
    static func parse(_ bytes: [UInt8]) throws -> (frame: PN532Frame, consumed: Int) {
        guard bytes.count >= 6 else { throw PN532Error.invalidFrame }
        
        var offset = 0
        
        // Skip leading zeros (but keep structure for ACK)
        if bytes.starts(with: ack) {
            return (PN532Frame(tfi: .hostToPN532, data: []), ack.count)
        }
        if bytes.starts(with: nack) {
            throw PN532Error.nackReceived
        }
        
        // Find 0x00 0xFF start code (allow 0 or more preamble 0x00)
        while offset + 1 < bytes.count {
            if bytes[offset] == 0x00 && bytes[offset + 1] == 0xFF {
                break
            }
            if bytes[offset] == 0x00 {
                offset += 1
                continue
            }
            // skip junk
            offset += 1
        }
        guard offset + 1 < bytes.count, bytes[offset] == 0x00, bytes[offset + 1] == 0xFF else {
            throw PN532Error.invalidFrame
        }
        offset += 2
        
        guard offset < bytes.count else { throw PN532Error.invalidFrame }
        let len = bytes[offset]
        offset += 1
        
        let payloadLength: Int
        if len == 0xFF {
            // Could be ACK length? Normal ACK is LEN=0 not 0xFF.
            // Extended frame: next two bytes may be 0xFF 0xFF marker already consumed? Standard:
            // 00 00 FF FF FF LENm LENl LCS ...
            // After start 00 FF, first len byte 0xFF means extended if next is 0xFF
            guard offset < bytes.count else { throw PN532Error.invalidFrame }
            if bytes[offset] == 0xFF {
                offset += 1
                guard offset + 1 < bytes.count else { throw PN532Error.invalidFrame }
                let extLen = (UInt16(bytes[offset]) << 8) | UInt16(bytes[offset + 1])
                offset += 2
                guard offset + 1 < bytes.count else { throw PN532Error.invalidFrame }
                offset += 2 // skip LCS
                payloadLength = Int(extLen)
            } else {
                // Normal frame with len=0xFF is invalid for standard; treat as incomplete
                throw PN532Error.invalidFrame
            }
        } else if len == 0x00 {
            // ACK: 00 00 FF 00 FF 00
            guard offset < bytes.count else { throw PN532Error.invalidFrame }
            let lcs = bytes[offset]
            offset += 1
            guard lcs == 0xFF else { throw PN532Error.invalidFrame }
            // optional postamble
            var consumed = offset
            if consumed < bytes.count && bytes[consumed] == 0x00 { consumed += 1 }
            return (PN532Frame(tfi: .hostToPN532, data: []), consumed)
        } else {
            guard offset < bytes.count else { throw PN532Error.invalidFrame }
            let lcs = bytes[offset]
            let expectedLcs = (0x0100 - UInt16(len)) & 0xFF
            guard UInt8(expectedLcs) == lcs else { throw PN532Error.invalidFrame }
            offset += 1
            payloadLength = Int(len)
        }
        
        let dcsIndex = offset + payloadLength
        guard dcsIndex < bytes.count else { throw PN532Error.invalidFrame }
        let payload = Array(bytes[offset..<dcsIndex])
        let dcs = bytes[dcsIndex]
        let sum = payload.reduce(0) { $0 &+ $1 }
        let expectedDcs = (0x0100 - UInt16(sum)) & 0xFF
        guard UInt8(expectedDcs) == dcs else { throw PN532Error.invalidFrame }
        
        if payload.first == errorTFI {
            let errorCode = payload.count > 1 ? payload[1] : 0
            throw PN532Error.hardwareError(errorCode)
        }
        
        guard let firstByte = payload.first else { throw PN532Error.invalidFrame }
        let tfi: TFI
        if firstByte == TFI.hostToPN532.rawValue {
            tfi = .hostToPN532
        } else if firstByte == TFI.pn532ToHost.rawValue {
            tfi = .pn532ToHost
        } else {
            throw PN532Error.invalidFrame
        }
        
        let frameData = Array(payload.dropFirst())
        var consumed = dcsIndex + 1
        // Consume optional postamble 0x00
        if consumed < bytes.count && bytes[consumed] == 0x00 { consumed += 1 }
        return (PN532Frame(tfi: tfi, data: frameData), consumed)
    }
}

// MARK: - PN532 Response Buffer Manager
class PN532ResponseBuffer {
    private var buffer = [UInt8]()
    private let maxBufferSize = 4096
    private let lock = NSLock()
    
    func append(_ data: [UInt8]) {
        lock.lock()
        defer { lock.unlock() }
        buffer.append(contentsOf: data)
        if buffer.count > maxBufferSize {
            buffer = Array(buffer.suffix(maxBufferSize))
        }
    }
    
    func append(_ data: Data) {
        append([UInt8](data))
    }
    
    /// Extract next complete frame. ACK frames have empty data + hostToPN532.
    func extractFrame() throws -> PN532Frame? {
        lock.lock()
        defer { lock.unlock() }
        guard buffer.count >= 6 else { return nil }
        
        // Align to possible frame start
        var startOffset = 0
        while startOffset < buffer.count - 2 {
            if buffer[startOffset] == 0x00 && startOffset + 1 < buffer.count && buffer[startOffset + 1] == 0x00 &&
                startOffset + 2 < buffer.count && buffer[startOffset + 2] == 0xFF {
                break
            }
            if buffer[startOffset] == 0x00 && startOffset + 1 < buffer.count && buffer[startOffset + 1] == 0xFF {
                break
            }
            startOffset += 1
        }
        
        if startOffset > 0 {
            if startOffset >= buffer.count {
                buffer.removeAll()
                return nil
            }
            buffer.removeFirst(startOffset)
        }
        
        guard buffer.count >= 6 else { return nil }
        
        do {
            let (frame, consumed) = try PN532Frame.parse(buffer)
            if consumed > 0 && consumed <= buffer.count {
                buffer.removeFirst(consumed)
            }
            return frame
        } catch PN532Error.invalidFrame {
            // incomplete
            return nil
        } catch {
            // NACK / hardware — drop minimal and rethrow
            if buffer.count > 6 {
                buffer.removeFirst(1)
            }
            throw error
        }
    }
    
    func clear() {
        lock.lock()
        defer { lock.unlock() }
        buffer.removeAll()
    }
}

// MARK: - Card Type Detection
struct CardInfo {
    let uid: [UInt8]
    let sak: UInt8
    let atqa: (UInt8, UInt8)
    let ats: [UInt8]?
    
    var uidString: String {
        uid.map { String(format: "%02X", $0) }.joined(separator: ":")
    }
    
    var typeDescription: String {
        switch sak {
        case 0x08: return "MIFARE Classic 1K"
        case 0x09: return "MIFARE Classic Mini"
        case 0x18: return "MIFARE Classic 4K"
        case 0x28: return "MIFARE Plus 2K SL1"
        case 0x38: return "MIFARE Plus 4K SL1"
        case 0x20: return "MIFARE Ultralight / NTAG"
        case 0x00: return "MIFARE Ultralight"
        case 0x44: return "MIFARE DESFire"
        case 0x34: return "MIFARE DESFire 8K"
        default:
            if uid.count == 4 { return "MIFARE Classic (4-byte UID)" }
            if uid.count == 7 { return "MIFARE Classic (7-byte UID)" }
            return "Unknown (SAK: 0x\(String(format: "%02X", sak)))"
        }
    }
    
    var isMifareClassic: Bool {
        [0x08, 0x09, 0x18].contains(sak) || (sak & 0x18) != 0
    }
    
    var isMagicCard: Bool {
        uid.first == 0x08 || uid.first == 0x09 || uid.first == 0x88
    }
    
    var totalSectors: Int {
        switch sak {
        case 0x08, 0x09: return 16
        case 0x18: return 40
        case 0x28, 0x38: return 40
        default: return 16
        }
    }
    
    var totalBlocks: Int {
        switch sak {
        case 0x08: return 64
        case 0x09: return 20
        case 0x18: return 256
        default: return 64
        }
    }
}