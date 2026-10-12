import Foundation
#if canImport(UIKit)
import UIKit
#endif

// MARK: - Hex Utilities
struct HexUtils {
    /// Convert byte array to hex string with optional separator
    static func bytesToHex(_ bytes: [UInt8], separator: String = " ") -> String {
        bytes.map { String(format: "%02X", $0) }.joined(separator: separator)
    }
    
    /// Convert hex string to byte array
    static func hexToBytes(_ hex: String) -> [UInt8] {
        let cleaned = hex
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: ":", with: "")
            .replacingOccurrences(of: "-", with: "")
            .replacingOccurrences(of: "0x", with: "")
            .replacingOccurrences(of: "0X", with: "")
        
        guard cleaned.count.isMultiple(of: 2), cleaned.count > 0 else { return [] }
        
        var bytes = [UInt8]()
        var index = cleaned.startIndex
        while index < cleaned.endIndex {
            let nextIndex = cleaned.index(index, offsetBy: 2)
            if let byte = UInt8(cleaned[index..<nextIndex], radix: 16) {
                bytes.append(byte)
            }
            index = nextIndex
        }
        return bytes
    }
    
    /// Validate hex string
    static func isValidHex(_ hex: String) -> Bool {
        let cleaned = hex
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: ":", with: "")
            .replacingOccurrences(of: "-", with: "")
            .replacingOccurrences(of: "0x", with: "")
            .replacingOccurrences(of: "0X", with: "")
        
        guard cleaned.count > 0 else { return false }
        let allowedChars = CharacterSet(charactersIn: "0123456789ABCDEFabcdef")
        return cleaned.rangeOfCharacter(from: allowedChars.inverted) == nil
    }
    
    /// Format bytes as ASCII (printable chars only)
    static func bytesToASCII(_ bytes: [UInt8]) -> String {
        String(bytes.map { byte -> Character in
            Character(UnicodeScalar(byte >= 32 && byte < 127 ? byte : 46)) // 46 = '.'
        })
    }
    
    /// XOR two byte arrays
    static func xor(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        zip(a, b).map { $0 ^ $1 }
    }
    
    /// Calculate CRC-A (used in MIFARE)
    static func crcA(_ data: [UInt8]) -> UInt16 {
        var crc: UInt16 = 0x6363
        for byte in data {
            crc ^= UInt16(byte)
            for _ in 0..<8 {
                if (crc & 0x0001) != 0 {
                    crc = (crc >> 1) ^ 0x8408
                } else {
                    crc >>= 1
                }
            }
        }
        return crc
    }
    
    /// Format dump as hex view (16 bytes per line)
    static func formatHexDump(_ data: [UInt8], startOffset: Int = 0, bytesPerLine: Int = 16) -> String {
        var result = ""
        var offset = startOffset
        
        var i = 0
        while i < data.count {
            let lineEnd = min(i + bytesPerLine, data.count)
            let lineData = Array(data[i..<lineEnd])
            
            // Offset
            result += String(format: "%04X  ", offset)
            
            // Hex bytes
            for byte in lineData {
                result += String(format: "%02X ", byte)
            }
            
            // Padding for incomplete line
            if lineData.count < bytesPerLine {
                result += String(repeating: "   ", count: bytesPerLine - lineData.count)
            }
            
            // ASCII representation
            result += " "
            for byte in lineData {
                let ch = (byte >= 32 && byte < 127) ? Character(UnicodeScalar(byte)) : "."
                result += String(ch)
            }
            
            result += "\n"
            offset += bytesPerLine
            i = lineEnd
        }
        
        return result
    }
    
    /// Pretty print a MIFARE key
    static func formatKey(_ key: [UInt8]) -> String {
        guard key.count == 6 else { return "无效密钥" }
        return bytesToHex(key, separator: " ")
    }
    
    /// Format a UID with colons
    static func formatUID(_ uid: [UInt8]) -> String {
        uid.map { String(format: "%02X", $0) }.joined(separator: ":")
    }
}

// MARK: - String Padding Extension
extension String {
    func padding(toLength length: Int, withPad pad: String, startingAt index: Int) -> String {
        let currentLength = self.count
        if currentLength >= length {
            return self
        }
        let paddingCount = length - currentLength
        let padding = String(repeating: pad, count: paddingCount)
        return padding + self
    }
}

// MARK: - Data Extensions
extension Data {
    var hexString: String {
        self.map { String(format: "%02X", $0) }.joined(separator: " ")
    }
    
    func writeToDocuments(filename: String) -> URL? {
        let paths = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)
        let url = paths[0].appendingPathComponent(filename)
        do {
            try self.write(to: url)
            return url
        } catch {
            return nil
        }
    }
}

// MARK: - File Operations
struct DumpFileManager {
    static let dumpsDirectory = "dumps"
    static let keysDirectory = "keys"
    
    /// Get documents directory URL
    static func documentsDir() -> URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }
    
    /// Get dump directory (create if needed)
    static func dumpsDir() -> URL {
        let dir = documentsDir().appendingPathComponent(dumpsDirectory)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }
    
    /// Get keys directory
    static func keysDir() -> URL {
        let dir = documentsDir().appendingPathComponent(keysDirectory)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }
    
    /// Save dump as binary .mfd file
    static func saveDump(_ dump: MIFAREDump) -> URL? {
        let data = dump.toBinary()
        let filename = "\(dump.uidString.replacingOccurrences(of: ":", with: ""))_\(dump.name).mfd"
        let url = dumpsDir().appendingPathComponent(filename)
        do {
            try data.write(to: url)
            return url
        } catch {
            return nil
        }
    }
    
    /// Load dump from .mfd file
    static func loadDump(from url: URL) -> MIFAREDump? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        let name = url.deletingPathExtension().lastPathComponent
        return MIFAREDump.fromBinary(data, name: name)
    }
    
    /// List all saved dumps
    static func listDumps() -> [URL] {
        let dir = dumpsDir()
        guard let files = try? FileManager.default.contentsOfDirectory(at: dir,
            includingPropertiesForKeys: nil) else { return [] }
        return files.filter { $0.pathExtension == "mfd" }
    }
    
    /// Save key file
    static func saveKeyFile(_ keys: [String: [UInt8]], filename: String) -> URL? {
        var content = "# PCR532 Key File\n"
        content += "# Format: sector:key_type:hex_key\n"
        content += "# key_type: A or B\n\n"
        
        for (sectorLabel, key) in keys.sorted(by: { $0.key < $1.key }) {
            content += "\(sectorLabel):\(HexUtils.bytesToHex(key))\n"
        }
        
        let url = keysDir().appendingPathComponent(filename)
        do {
            try content.write(to: url, atomically: true, encoding: .utf8)
            return url
        } catch {
            return nil
        }
    }
    
    /// Load key file
    static func loadKeyFile(from url: URL) -> [String: [UInt8]] {
        guard let content = try? String(contentsOf: url, encoding: .utf8) else { return [:] }
        
        var keys = [String: [UInt8]]()
        for line in content.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { continue }
            
            let parts = trimmed.components(separatedBy: ":")
            if parts.count >= 2 {
                let sectorKey = parts[0]
                let hexKey = parts.dropFirst().joined()
                if let bytes = UInt8.hexToBytes(hexKey), bytes.count == 6 {
                    keys[sectorKey] = bytes
                }
            }
        }
        return keys
    }
}

// MARK: - Haptic Feedback Manager
@MainActor
enum HapticFeedback {
    static func success() {
        UINotificationFeedbackGenerator().notificationOccurred(.success)
    }
    static func error() {
        UINotificationFeedbackGenerator().notificationOccurred(.error)
    }
    static func warning() {
        UINotificationFeedbackGenerator().notificationOccurred(.warning)
    }
    static func selection() {
        UISelectionFeedbackGenerator().selectionChanged()
    }
    static func impact(_ style: UIImpactFeedbackGenerator.FeedbackStyle = .medium) {
        UIImpactFeedbackGenerator(style: style).impactOccurred()
    }
}

// MARK: - KeyStore (Persistent key storage with UserDefaults)
@MainActor
class KeyStore: ObservableObject {
    static let shared = KeyStore()
    @Published var savedKeys = [(String, [UInt8])]()  // (label, key)
    
    private let defaults = UserDefaults.standard
    private let keyPrefix = "pcr532_saved_key_"
    private let labelPrefix = "pcr532_saved_label_"
    private let countKey = "pcr532_saved_key_count"
    
    init() {
        loadKeys()
    }
    
    func loadKeys() {
        savedKeys.removeAll()
        let count = defaults.integer(forKey: countKey)
        for i in 0..<count {
            if let keyData = defaults.data(forKey: "\(keyPrefix)\(i)"),
               let label = defaults.string(forKey: "\(labelPrefix)\(i)"),
               keyData.count == 6 {
                let key = [UInt8](keyData)
                savedKeys.append((label, key))
            }
        }
    }
    
    func hasKey(_ key: [UInt8]) -> Bool {
        savedKeys.contains { $0.1 == key }
    }
    
    @discardableResult
    func saveKeyIfNotExists(label: String, key: [UInt8]) -> Bool {
        guard key.count == 6 else { return false }
        if hasKey(key) { return false }
        saveKey(label: label, key: key)
        return true
    }
    
    func saveMultipleKeys(_ keys: [(String, [UInt8])]) -> Int {
        var added = 0
        for item in keys {
            if saveKeyIfNotExists(label: item.0, key: item.1) {
                added += 1
            }
        }
        return added
    }
    
    func saveKey(label: String, key: [UInt8]) {
        let count = defaults.integer(forKey: countKey)
        defaults.set(Data(key), forKey: "\(keyPrefix)\(count)")
        defaults.set(label, forKey: "\(labelPrefix)\(count)")
        defaults.set(count + 1, forKey: countKey)
        savedKeys.append((label, key))
    }
    
    func deleteKey(at index: Int) {
        guard index < savedKeys.count else { return }
        savedKeys.remove(at: index)
        
        // Rewrite all keys
        defaults.set(0, forKey: countKey)
        for i in 0..<savedKeys.count {
            defaults.set(Data(savedKeys[i].1), forKey: "\(keyPrefix)\(i)")
            defaults.set(savedKeys[i].0, forKey: "\(labelPrefix)\(i)")
        }
        defaults.set(savedKeys.count, forKey: countKey)
    }
    
    func allKeys() -> [[UInt8]] {
        savedKeys.map { $0.1 }
    }
}

// MARK: - UInt8 Array Extension
extension UInt8 {
    static func hexToBytes(_ hex: String) -> [UInt8]? {
        let cleaned = hex
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: ":", with: "")
            .replacingOccurrences(of: "-", with: "")
            .replacingOccurrences(of: "0x", with: "")
            .replacingOccurrences(of: "0X", with: "")
        
        guard cleaned.count.isMultiple(of: 2), cleaned.count >= 2 else { return nil }
        
        var bytes = [UInt8]()
        var index = cleaned.startIndex
        while index < cleaned.endIndex {
            let nextIndex = cleaned.index(index, offsetBy: 2)
            if let byte = UInt8(cleaned[index..<nextIndex], radix: 16) {
                bytes.append(byte)
            } else {
                return nil
            }
            index = nextIndex
        }
        return bytes
    }
}