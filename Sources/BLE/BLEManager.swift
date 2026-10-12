import Foundation
import CoreBluetooth

struct PCR532BLE {
    static let sppUUID = CBUUID(string: "00001101-0000-1000-8000-00805F9B34FB")
    static let nordicService = CBUUID(string: "6E400001-B5A3-F393-E0A9-E50E24DCCA9E")
    static let nordicWrite = CBUUID(string: "6E400002-B5A3-F393-E0A9-E50E24DCCA9E")
    static let nordicNotify = CBUUID(string: "6E400003-B5A3-F393-E0A9-E50E24DCCA9E")
    static let ffe0 = CBUUID(string: "0000FFE0-0000-1000-8000-00805F9B34FB")
    static let ffe1 = CBUUID(string: "0000FFE1-0000-1000-8000-00805F9B34FB")
    static let fff0 = CBUUID(string: "0000FFF0-0000-1000-8000-00805F9B34FB")
    static let fff1 = CBUUID(string: "0000FFF1-0000-1000-8000-00805F9B34FB")
    static let fff2 = CBUUID(string: "0000FFF2-0000-1000-8000-00805F9B34FB")
    static let fff3 = CBUUID(string: "0000FFF3-0000-1000-8000-00805F9B34FB")
    
    /// libnfc pn532_uart_wakeup: 0x55 0x55 + 14 * 0x00
    static let wakeUp: [UInt8] = [0x55, 0x55] + [UInt8](repeating: 0x00, count: 14)
}

protocol BLEManagerDelegate: AnyObject {
    func bleDidUpdateState(_ isPoweredOn: Bool)
    func bleDidDiscoverDevice(_ device: BLEDevice)
    func bleDidConnect(_ device: BLEDevice)
    func bleDidDisconnect(_ device: BLEDevice, error: Error?)
    func bleDidReceiveData(_ data: [UInt8])
    func bleDidEncounterError(_ error: Error)
}

struct BLEDevice: Identifiable, Equatable {
    let id: UUID
    let name: String
    let rssi: Int
    let peripheral: CBPeripheral
    static func == (lhs: BLEDevice, rhs: BLEDevice) -> Bool { lhs.id == rhs.id }
    var signalBars: Int {
        if rssi >= -50 { return 4 }
        if rssi >= -65 { return 3 }
        if rssi >= -80 { return 2 }
        if rssi >= -90 { return 1 }
        return 0
    }
}

@MainActor
private class AsyncLock {
    private var isLocked = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    
    func lock() async {
        if !isLocked {
            isLocked = true
            return
        }
        await withCheckedContinuation { cont in
            waiters.append(cont)
        }
    }
    
    func unlock() {
        if !waiters.isEmpty {
            let next = waiters.removeFirst()
            next.resume()
        } else {
            isLocked = false
        }
    }
}

@MainActor
class BLEManager: NSObject, ObservableObject {
    @Published var isScanning = false
    @Published var isConnected = false
    @Published var connectedDeviceName = ""
    @Published var discoveredDevices = [BLEDevice]()
    @Published var connectionState: ConnectionState = .disconnected
    @Published var lastErrorMessage: String?
    @Published var lastDebugLog: String = ""
    
    enum ConnectionState: String {
        case disconnected = "Not connected"
        case connecting = "Connecting..."
        case discovering = "Discovering..."
        case ready = "Ready"
    }
    
    weak var delegate: BLEManagerDelegate?
    
    private var centralManager: CBCentralManager!
    private var connectedPeripheral: CBPeripheral?
    private var writeCharacteristic: CBCharacteristic?
    private var notifyCharacteristic: CBCharacteristic?
    private var candidateWrite: [CBCharacteristic] = []
    private var candidateNotify: [CBCharacteristic] = []
    private var allCharacteristics: [CBCharacteristic] = []
    private var responseBuffer = PN532ResponseBuffer()
    private var frameWaitContinuation: CheckedContinuation<PN532Frame, Error>?
    private var timeoutWorkItem: DispatchWorkItem?
    private let sendLock = AsyncLock()
    private var didInitPN532 = false
    private var linkVerified = false
    private var mtuChunkSize = 20
    private var useWithoutResponse = true
    private var rxByteCount: Int = 0
    private var debugLines: [String] = []
    private var lastTxTime: Date = .distantPast
    
    override init() {
        super.init()
        centralManager = CBCentralManager(delegate: self, queue: .main)
    }
    
    func startScan() { startScanAll() }
    
    func startScanFilteredByService() {
        guard centralManager.state == .poweredOn else { return }
        discoveredDevices.removeAll()
        isScanning = true
        centralManager.scanForPeripherals(withServices: [
            PCR532BLE.sppUUID, PCR532BLE.nordicService, PCR532BLE.ffe0, PCR532BLE.fff0
        ], options: [CBCentralManagerScanOptionAllowDuplicatesKey: false])
    }
    
    func startScanAll() {
        guard centralManager.state == .poweredOn else {
            lastErrorMessage = "Bluetooth is off"
            return
        }
        discoveredDevices.removeAll()
        isScanning = true
        centralManager.scanForPeripherals(withServices: nil,
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: false])
    }
    
    func stopScan() {
        isScanning = false
        centralManager.stopScan()
    }
    
    func connect(to device: BLEDevice) {
        connectionState = .connecting
        lastErrorMessage = nil
        didInitPN532 = false
        linkVerified = false
        rxByteCount = 0
        writeCharacteristic = nil
        notifyCharacteristic = nil
        candidateWrite.removeAll()
        candidateNotify.removeAll()
        allCharacteristics.removeAll()
        responseBuffer.clear()
        debugLines.removeAll()
        stopScan()
        centralManager.connect(device.peripheral, options: nil)
        connectedPeripheral = device.peripheral
        connectedPeripheral?.delegate = self
    }
    
    func disconnect() {
        guard let p = connectedPeripheral else { return }
        failPending(PN532Error.notConnected)
        centralManager.cancelPeripheralConnection(p)
    }
    
    /// libnfc-style: wake + frame, wait ACK then response. Auto-probe write/notify mapping.
    func sendFrame(_ frame: PN532Frame, timeout: TimeInterval = 8.0) async throws -> PN532Frame {
        guard let peripheral = connectedPeripheral else { throw PN532Error.notConnected }
        guard connectionState == .ready else {
            throw PN532Error.communicationError("Not ready")
        }
        
        await sendLock.lock()
        defer { 
            lastTxTime = Date()
            sendLock.unlock() 
        }
        
        if !didInitPN532 {
            try await probeAndInit()
        }
        
        // If idle for >150ms, wake up PN532 first, then pause 15ms for clock stabilization
        let isIdle = Date().timeIntervalSince(lastTxTime) > 0.15
        if isIdle {
            try? await writeBytes(PCR532BLE.wakeUp, peripheral: peripheral)
            try? await Task.sleep(nanoseconds: 15_000_000)
        }
        
        let payload = frame.encode()
        let stream = payload
        
        // Fast path: if link is already verified, use active characteristics directly.
        // Send clean payload without prepended wake preamble to avoid MTU packet splitting & UART frame errors.
        if linkVerified, let writeChar = writeCharacteristic {
            responseBuffer.clear()
            appendDebug("TX W=\(short(writeChar.uuid)) N=\(short(notifyCharacteristic?.uuid)) WOR=\(useWithoutResponse) \(hex(stream))")
            try await writeBytes(stream, peripheral: peripheral)
            
            let deadline = Date().addingTimeInterval(timeout)
            while Date() < deadline {
                let rem = max(deadline.timeIntervalSinceNow, 0.05)
                let resp = try await waitForNextFrame(timeout: rem)
                if resp.isAckPlaceholder {
                    appendDebug("RX ACK")
                    continue
                }
                if resp.tfi == .pn532ToHost {
                    appendDebug("RX \(hex(resp.data))")
                    return resp
                }
            }
            throw PN532Error.timeout
        }
        
        let maps = buildCharMaps()
        // Prefer last known good map first
        var ordered = maps
        if let w = writeCharacteristic, let n = notifyCharacteristic {
            ordered.insert(CharMap(write: w, notify: n, withoutResponse: useWithoutResponse), at: 0)
        }
        
        var lastError: Error = PN532Error.timeout
        // Deduplicate maps
        var seen = Set<String>()
        let uniqueMaps = ordered.filter { m in
            let key = "\(m.write.uuid.uuidString)|\(m.notify?.uuid.uuidString ?? "-")|\(m.withoutResponse)"
            if seen.contains(key) { return false }
            seen.insert(key)
            return true
        }
        
        for (idx, map) in uniqueMaps.enumerated() {
            writeCharacteristic = map.write
            notifyCharacteristic = map.notify
            useWithoutResponse = map.withoutResponse
            if let n = map.notify {
                peripheral.setNotifyValue(true, for: n)
            }
            // Ensure all notify chars subscribed
            for n in candidateNotify {
                peripheral.setNotifyValue(true, for: n)
            }
            
            responseBuffer.clear()
            // CRITICAL (libnfc): wake preamble immediately before every command
            appendDebug("TX#\(idx) W=\(short(map.write.uuid)) N=\(short(map.notify?.uuid)) WOR=\(map.withoutResponse) \(hex(stream))")
            
            do {
                try await writeBytes(stream, peripheral: peripheral)
            } catch {
                lastError = error
                appendDebug("write err: \(error.localizedDescription)")
                continue
            }
            
            let deadline = Date().addingTimeInterval(min(timeout, 2.0))
            do {
                while Date() < deadline {
                    let rem = max(deadline.timeIntervalSinceNow, 0.05)
                    let resp = try await waitForNextFrame(timeout: rem)
                    if resp.isAckPlaceholder {
                        appendDebug("RX ACK")
                        continue
                    }
                    if resp.tfi == .pn532ToHost {
                        appendDebug("RX \(hex(resp.data))")
                        linkVerified = true
                        return resp
                    }
                }
            } catch let e as PN532Error {
                if case .timeout = e {
                    appendDebug("map#\(idx) timeout rx=\(rxByteCount)")
                    lastError = e
                    continue
                }
                throw e
            } catch {
                lastError = error
            }
        }
        
        appendDebug("FAIL no RX (rxBytes=\(rxByteCount) writes=\(candidateWrite.count) notifys=\(candidateNotify.count))")
        throw lastError
    }
    
    func sendRaw(_ data: [UInt8]) {
        guard let peripheral = connectedPeripheral, connectionState == .ready else { return }
        Task { try? await writeBytes(data, peripheral: peripheral) }
    }
    
    // MARK: - Probe all UART mappings with GetFirmwareVersion
    
    private func probeAndInit() async throws {
        guard let peripheral = connectedPeripheral else { throw PN532Error.notConnected }
        
        // Subscribe everything notifiable first
        for n in candidateNotify {
            peripheral.setNotifyValue(true, for: n)
        }
        try await Task.sleep(nanoseconds: 300_000_000)
        
        let fw = PN532Frame(tfi: .hostToPN532, data: [0x02]).encode()
        let sam = PN532Frame(tfi: .hostToPN532, data: [0x14, 0x01, 0x14, 0x01]).encode()
        let maps = buildCharMaps()
        appendDebug("Probe maps=\(maps.count) W=\(candidateWrite.count) N=\(candidateNotify.count)")
        
        for (idx, map) in maps.enumerated() {
            writeCharacteristic = map.write
            notifyCharacteristic = map.notify
            useWithoutResponse = map.withoutResponse
            if let n = map.notify {
                peripheral.setNotifyValue(true, for: n)
            }
            responseBuffer.clear()
            let beforeRX = rxByteCount
            
            // wake + SAM
            try? await writeBytes(PCR532BLE.wakeUp + sam, peripheral: peripheral)
            _ = try? await waitAckThenData(timeout: 1.5)
            
            // wake + GetFirmware
            responseBuffer.clear()
            try? await writeBytes(PCR532BLE.wakeUp + fw, peripheral: peripheral)
            if let resp = try? await waitAckThenData(timeout: 2.5), resp.tfi == .pn532ToHost {
                appendDebug("LINK OK map#\(idx) FW \(hex(resp.data)) W=\(short(map.write.uuid))")
                didInitPN532 = true
                linkVerified = true
                return
            }
            
            // Also try frame-only (no wake) — some BLE bridges already keep PN532 awake
            responseBuffer.clear()
            try? await writeBytes(fw, peripheral: peripheral)
            if let resp = try? await waitAckThenData(timeout: 2.0), resp.tfi == .pn532ToHost {
                appendDebug("LINK OK nowake map#\(idx) FW \(hex(resp.data))")
                didInitPN532 = true
                linkVerified = true
                return
            }
            
            if rxByteCount > beforeRX {
                appendDebug("map#\(idx) got \(rxByteCount - beforeRX) raw bytes (parse fail?)")
            }
        }
        
        // Still mark init done so detect can multi-map retry; but flag weak
        didInitPN532 = true
        linkVerified = false
        appendDebug("No PN532 ACK yet — will retry maps on each cmd")
    }
    
    private struct CharMap {
        let write: CBCharacteristic
        let notify: CBCharacteristic?
        let withoutResponse: Bool
    }
    
    private func buildCharMaps() -> [CharMap] {
        var maps: [CharMap] = []
        let writes = candidateWrite.sorted { scoreWrite($0) > scoreWrite($1) }
        let notifys = candidateNotify.sorted { scoreNotify($0) > scoreNotify($1) }
        
        func add(_ w: CBCharacteristic, _ n: CBCharacteristic?, _ wor: Bool) {
            maps.append(CharMap(write: w, notify: n, withoutResponse: wor))
        }
        
        // Known pairs first
        for w in writes {
            for n in notifys {
                let canWOR = w.properties.contains(.writeWithoutResponse)
                let canW = w.properties.contains(.write)
                if canWOR { add(w, n, true) }
                if canW { add(w, n, false) }
            }
            // dual role single char
            if w.properties.contains(.notify) || w.properties.contains(.indicate) {
                let canWOR = w.properties.contains(.writeWithoutResponse)
                if canWOR { add(w, w, true) }
                if w.properties.contains(.write) { add(w, w, false) }
            }
        }
        
        // If no notify candidates, still try writes (some modules use indicate later)
        if notifys.isEmpty {
            for w in writes {
                if w.properties.contains(.writeWithoutResponse) { add(w, nil, true) }
                if w.properties.contains(.write) { add(w, nil, false) }
            }
        }
        
        return maps
    }
    
    private func scoreWrite(_ c: CBCharacteristic) -> Int {
        var s = 0
        let u = c.uuid
        if u == PCR532BLE.nordicWrite { s += 100 }
        if u == PCR532BLE.ffe1 { s += 95 }
        if u == PCR532BLE.fff1 { s += 90 }
        if u == PCR532BLE.fff2 { s += 80 }
        if c.properties.contains(.writeWithoutResponse) { s += 15 }
        if c.properties.contains(.write) { s += 8 }
        return s
    }
    
    private func scoreNotify(_ c: CBCharacteristic) -> Int {
        var s = 0
        let u = c.uuid
        if u == PCR532BLE.nordicNotify { s += 100 }
        if u == PCR532BLE.ffe1 { s += 95 }
        if u == PCR532BLE.fff2 { s += 90 }
        if u == PCR532BLE.fff1 { s += 80 }
        if c.properties.contains(.notify) { s += 15 }
        if c.properties.contains(.indicate) { s += 8 }
        return s
    }
    
    private func waitAckThenData(timeout: TimeInterval) async throws -> PN532Frame {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            let rem = max(deadline.timeIntervalSinceNow, 0.05)
            let resp = try await waitForNextFrame(timeout: rem)
            if resp.isAckPlaceholder { continue }
            return resp
        }
        throw PN532Error.timeout
    }
    
    private func waitForNextFrame(timeout: TimeInterval) async throws -> PN532Frame {
        if let frame = try responseBuffer.extractFrame() {
            return frame
        }
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<PN532Frame, Error>) in
            self.frameWaitContinuation = cont
            let workItem = DispatchWorkItem { [weak self] in
                guard let self = self else { return }
                if let c = self.frameWaitContinuation {
                    self.frameWaitContinuation = nil
                    self.timeoutWorkItem = nil
                    c.resume(throwing: PN532Error.timeout)
                }
            }
            self.timeoutWorkItem = workItem
            DispatchQueue.main.asyncAfter(deadline: .now() + timeout, execute: workItem)
        }
    }
    
    private func failPending(_ error: Error) {
        timeoutWorkItem?.cancel()
        timeoutWorkItem = nil
        if let c = frameWaitContinuation {
            frameWaitContinuation = nil
            c.resume(throwing: error)
        }
    }
    
    private func deliverBufferedFrames() {
        do {
            while let frame = try responseBuffer.extractFrame() {
                if let c = frameWaitContinuation {
                    timeoutWorkItem?.cancel()
                    timeoutWorkItem = nil
                    frameWaitContinuation = nil
                    c.resume(returning: frame)
                    return
                } else {
                    break
                }
            }
        } catch {
            if let c = frameWaitContinuation {
                timeoutWorkItem?.cancel()
                timeoutWorkItem = nil
                frameWaitContinuation = nil
                c.resume(throwing: error)
            }
        }
    }
    
    private func writeBytes(_ data: [UInt8], peripheral: CBPeripheral) async throws {
        guard let writeChar = writeCharacteristic else {
            throw PN532Error.communicationError("No write char")
        }
        
        let canWOR = writeChar.properties.contains(.writeWithoutResponse)
        let canW = writeChar.properties.contains(.write)
        let writeType: CBCharacteristicWriteType = {
            if useWithoutResponse && canWOR { return .withoutResponse }
            if canW { return .withResponse }
            if canWOR { return .withoutResponse }
            return .withResponse
        }()
        
        let maxOnce = peripheral.maximumWriteValueLength(for: writeType)
        let chunkSize = max(20, maxOnce > 0 ? min(maxOnce, 180) : mtuChunkSize)
        
        // Prefer single packet for frame (PN532 frames are usually 7-20 bytes)
        if data.count <= chunkSize {
            peripheral.writeValue(Data(data), for: writeChar, type: writeType)
            try await Task.sleep(nanoseconds: 10_000_000)
            return
        }
        
        var offset = 0
        while offset < data.count {
            let end = min(offset + chunkSize, data.count)
            peripheral.writeValue(Data(Array(data[offset..<end])), for: writeChar, type: writeType)
            offset = end
            try await Task.sleep(nanoseconds: 15_000_000)
        }
        try await Task.sleep(nanoseconds: 15_000_000)
    }
    
    private func appendDebug(_ s: String) {
        debugLines.append(s)
        if debugLines.count > 8 { debugLines.removeFirst(debugLines.count - 8) }
        lastDebugLog = debugLines.joined(separator: "\n")
    }
    
    private func hex(_ d: [UInt8]) -> String {
        d.map { String(format: "%02X", $0) }.joined(separator: " ")
    }
    
    private func short(_ uuid: CBUUID?) -> String {
        guard let uuid = uuid else { return "-" }
        let s = uuid.uuidString
        if s.count > 8 { return String(s.prefix(8)) }
        return s
    }
    
    private func markReadyIfPossible() {
        if !candidateWrite.isEmpty {
            writeCharacteristic = candidateWrite.sorted { scoreWrite($0) > scoreWrite($1) }.first
            notifyCharacteristic = candidateNotify.sorted { scoreNotify($0) > scoreNotify($1) }.first
            if let n = notifyCharacteristic, let p = connectedPeripheral {
                p.setNotifyValue(true, for: n)
            }
            for n in candidateNotify {
                connectedPeripheral?.setNotifyValue(true, for: n)
            }
            connectionState = .ready
            isConnected = true
            lastErrorMessage = nil
            let wdesc = candidateWrite.map { short($0.uuid) + props($0) }.joined(separator: ",")
            let ndesc = candidateNotify.map { short($0.uuid) + props($0) }.joined(separator: ",")
            appendDebug("Ready W:[\(wdesc)] N:[\(ndesc)]")
        }
    }
    
    private func props(_ c: CBCharacteristic) -> String {
        var p = ""
        if c.properties.contains(.write) { p += "W" }
        if c.properties.contains(.writeWithoutResponse) { p += "w" }
        if c.properties.contains(.notify) { p += "N" }
        if c.properties.contains(.indicate) { p += "I" }
        if c.properties.contains(.read) { p += "R" }
        return "(\(p))"
    }
}

extension BLEManager: @preconcurrency CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        delegate?.bleDidUpdateState(central.state == .poweredOn)
    }
    
    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                       advertisementData: [String: Any], rssi RSSI: NSNumber) {
        let advertisedName = advertisementData[CBAdvertisementDataLocalNameKey] as? String
        let name = peripheral.name ?? advertisedName ?? ""
        if name.isEmpty { return }
        let device = BLEDevice(id: peripheral.identifier, name: name, rssi: RSSI.intValue, peripheral: peripheral)
        if let i = discoveredDevices.firstIndex(where: { $0.id == device.id }) {
            discoveredDevices[i] = device
        } else {
            discoveredDevices.append(device)
            discoveredDevices.sort { $0.rssi > $1.rssi }
        }
        delegate?.bleDidDiscoverDevice(device)
    }
    
    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        connectionState = .discovering
        connectedDeviceName = peripheral.name ?? "PCR532"
        let maxLen = peripheral.maximumWriteValueLength(for: .withoutResponse)
        if maxLen > 0 { mtuChunkSize = max(20, min(maxLen, 180)) }
        delegate?.bleDidConnect(BLEDevice(id: peripheral.identifier, name: peripheral.name ?? "", rssi: 0, peripheral: peripheral))
        peripheral.discoverServices(nil)
    }
    
    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        connectionState = .disconnected
        isConnected = false
        lastErrorMessage = error?.localizedDescription ?? "Connect failed"
    }
    
    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        connectionState = .disconnected
        isConnected = false
        connectedDeviceName = ""
        writeCharacteristic = nil
        notifyCharacteristic = nil
        didInitPN532 = false
        linkVerified = false
        failPending(PN532Error.notConnected)
        delegate?.bleDidDisconnect(
            BLEDevice(id: peripheral.identifier, name: peripheral.name ?? "", rssi: 0, peripheral: peripheral),
            error: error
        )
    }
}

extension BLEManager: @preconcurrency CBPeripheralDelegate {
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        if let error = error {
            lastErrorMessage = error.localizedDescription
            return
        }
        let services = peripheral.services ?? []
        if services.isEmpty {
            lastErrorMessage = "No BLE services"
            connectionState = .disconnected
            return
        }
        appendDebug("SVC \(services.map { short($0.uuid) }.joined(separator: ","))")
        for s in services {
            peripheral.discoverCharacteristics(nil, for: s)
        }
    }
    
    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        if let error = error {
            lastErrorMessage = error.localizedDescription
            return
        }
        for c in service.characteristics ?? [] {
            allCharacteristics.append(c)
            let canW = c.properties.contains(.write) || c.properties.contains(.writeWithoutResponse)
            let canN = c.properties.contains(.notify) || c.properties.contains(.indicate)
            if canW { candidateWrite.append(c) }
            if canN {
                candidateNotify.append(c)
                peripheral.setNotifyValue(true, for: c)
            }
            // Some cheap modules mark UART char only as read+write; still try write
            if !canW && !canN && c.properties.contains(.read) {
                // skip pure read
            } else if !canW && c.properties.contains(.write) == false {
                // nothing
            }
        }
        
        // Ready when all services have characteristics discovered
        let pending = (peripheral.services ?? []).contains { $0.characteristics == nil }
        if !pending {
            markReadyIfPossible()
        }
    }
    
    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        if let error = error {
            appendDebug("notify err \(error.localizedDescription)")
            return
        }
        guard let value = characteristic.value, !value.isEmpty else { return }
        let bytes = [UInt8](value)
        rxByteCount += bytes.count
        appendDebug("RXN \(short(characteristic.uuid)) \(hex(bytes))")
        responseBuffer.append(bytes)
        deliverBufferedFrames()
        delegate?.bleDidReceiveData(bytes)
    }
    
    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        if let error = error {
            appendDebug("WRerr \(error.localizedDescription)")
            // Prefer withoutResponse next time
            useWithoutResponse = true
        }
    }
    
    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        if let error = error {
            appendDebug("CCCD err \(short(characteristic.uuid)): \(error.localizedDescription)")
        } else {
            appendDebug("CCCD on \(short(characteristic.uuid))")
        }
    }
}