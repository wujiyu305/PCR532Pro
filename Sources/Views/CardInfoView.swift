import SwiftUI
#if canImport(UIKit)
import UIKit

// MARK: - Native Share Sheet
struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}
#endif

// MARK: - Card Info View
struct CardInfoView: View {
    let cardInfo: CardInfo?
    @ObservedObject var mifareController: MIFAREController
    @ObservedObject var bleManager: BLEManager
    @ObservedObject var nestedAttack: NestedAttack
    @ObservedObject var magicController: MagicCardController
    
    @State private var isDetecting = false
    @State private var errorMessage: String?
    @State private var showDumpAlert = false
    @State private var dumpName = ""
    @State private var showWriteDumpSheet = false
    @State private var showMagicCardSheet = false
    @State private var shareURL: URL?
    @State private var showShareSheet = false
    @State private var showKeyInput = false
    @State private var isAutoDetecting = false
    @State private var autoDetectTimer: Timer?
    @State private var isPerformingNested = false
    
    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                if let card = cardInfo {
                    ZStack {
                        RoundedRectangle(cornerRadius: 16)
                            .fill(LinearGradient(
                                gradient: Gradient(colors: [.blue, .purple]),
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            ))
                            .frame(height: 120)
                        VStack(spacing: 8) {
                            Image(systemName: "creditcard.and.123")
                                .font(.system(size: 36))
                                .foregroundColor(.white)
                            Text(card.typeDescription)
                                .font(.headline)
                                .foregroundColor(.white)
                        }
                    }
                    .padding(.horizontal)
                    
                    VStack(alignment: .leading, spacing: 10) {
                        DetailRow(label: "UID", value: card.uidString)
                        DetailRow(label: "SAK", value: String(format: "0x%02X", card.sak))
                        DetailRow(label: "ATQA", value: String(format: "0x%02X%02X", card.atqa.0, card.atqa.1))
                        DetailRow(label: "Sectors", value: "\(card.totalSectors)")
                        DetailRow(label: "Blocks", value: "\(card.totalBlocks)")
                        if card.isMagicCard {
                            HStack {
                                Image(systemName: "wand.and.stars").foregroundColor(.yellow)
                                Text("Magic card (UID Writable)").foregroundColor(.yellow).fontWeight(.bold)
                            }
                        }
                    }
                    .padding()
                    .background(Color(.systemGray6))
                    .cornerRadius(12)
                    .padding(.horizontal)
                    
                    // Priority Key configuration
                    DisclosureGroup("指定优先密钥 (可选)", isExpanded: $showKeyInput) {
                        VStack(alignment: .leading, spacing: 8) {
                            TextField("6字节十六进制，如 FFFFFFFFFFFF", text: $mifareController.specifiedKeyHex)
                                .font(.system(.body, design: .monospaced))
                                .textInputAutocapitalization(.characters)
                                .disableAutocorrection(true)
                                .padding(8)
                                .background(Color(.systemBackground))
                                .cornerRadius(8)
                            Text("读卡时将优先尝试此密钥，匹配时可极大提升读取速度。")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                        .padding(.top, 4)
                    }
                    .padding()
                    .background(Color(.systemGray6))
                    .cornerRadius(12)
                    .padding(.horizontal)
                    
                    // Primary Action Buttons Grid
                    VStack(spacing: 10) {
                        HStack(spacing: 10) {
                            Button(action: { detectCard() }) {
                                Label(isDetecting ? "Detecting..." : "Detect", systemImage: "waveform.path.ecg")
                                    .frame(maxWidth: .infinity).padding(.vertical, 12)
                                    .background(Color.blue).foregroundColor(.white).cornerRadius(10)
                            }
                            .disabled(isDetecting || !bleManager.isConnected)
                            
                            Button(action: { readFullCard() }) {
                                Label("Dump", systemImage: "square.and.arrow.down")
                                    .frame(maxWidth: .infinity).padding(.vertical, 12)
                                    .background(Color.green).foregroundColor(.white).cornerRadius(10)
                            }
                            .disabled(mifareController.isReading || !bleManager.isConnected)
                            
                            Button(action: { showDumpAlert = true }) {
                                Label("Save", systemImage: "tray.and.arrow.down")
                                    .frame(maxWidth: .infinity).padding(.vertical, 12)
                                    .background(Color.orange).foregroundColor(.white).cornerRadius(10)
                            }
                            .disabled(mifareController.sectors.isEmpty)
                        }
                        
                        HStack(spacing: 8) {
                            Button(action: { showWriteDumpSheet = true }) {
                                Label("写卡", systemImage: "square.and.arrow.up")
                                    .frame(maxWidth: .infinity).padding(.vertical, 10)
                                    .background(Color.purple).foregroundColor(.white).cornerRadius(10)
                            }
                            .disabled(mifareController.isReading || !bleManager.isConnected)
                            
                            Button(action: { saveKeysToStore() }) {
                                Label("存Key", systemImage: "key.fill")
                                    .frame(maxWidth: .infinity).padding(.vertical, 10)
                                    .background(Color.teal).foregroundColor(.white).cornerRadius(10)
                            }
                            .disabled(mifareController.sectors.filter { $0.isAuthenticated }.isEmpty)
                            
                            Button(action: { showMagicCardSheet = true }) {
                                Label("魔术卡", systemImage: "wand.and.stars")
                                    .frame(maxWidth: .infinity).padding(.vertical, 10)
                                    .background(Color.pink).foregroundColor(.white).cornerRadius(10)
                            }
                            
                            Button(action: { exportAndShareMFD() }) {
                                Label("导出", systemImage: "square.and.arrow.up.on.square")
                                    .frame(maxWidth: .infinity).padding(.vertical, 10)
                                    .background(Color.indigo).foregroundColor(.white).cornerRadius(10)
                            }
                            .disabled(mifareController.sectors.isEmpty)
                        }
                    }
                    .padding(.horizontal)
                    
                    // High-frequency feature on Home: Nested Attack from known key
                    homeNestedAttackSection
                } else {
                    Spacer(minLength: 40)
                    Image(systemName: "creditcard").font(.system(size: 60)).foregroundColor(.gray)
                    Text("未检测到卡片").font(.headline).foregroundColor(.gray)
                    Text("请将 NFC 卡片贴近读卡器天线区域").font(.caption).foregroundColor(.secondary)
                    
                    Button(action: { detectCard() }) {
                        HStack {
                            if isDetecting { ProgressView().tint(.white) }
                            Text(isDetecting ? "正在感应卡片..." : "寻卡 (Detect Card)")
                        }
                        .frame(maxWidth: .infinity).padding()
                        .background(bleManager.isConnected ? Color.blue : Color.gray)
                        .foregroundColor(.white).cornerRadius(10)
                    }
                    .disabled(isDetecting || !bleManager.isConnected)
                    .padding(.horizontal, 40)
                    Spacer(minLength: 40)
                }
                
                // Auto-detect toggle
                Toggle("连续自动感应 (Auto Scan)", isOn: $isAutoDetecting)
                    .padding(.horizontal)
                    .onChange(of: isAutoDetecting) { enabled in
                        toggleAutoDetect(enabled)
                    }
                
                if mifareController.isReading {
                    VStack(spacing: 6) {
                        ProgressView(value: mifareController.progress)
                            .progressViewStyle(.linear)
                        Text(mifareController.statusMessage)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    .padding(.horizontal)
                } else if !mifareController.statusMessage.isEmpty {
                    Text(mifareController.statusMessage)
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }
                
                if let err = errorMessage {
                    Text(err).font(.caption).foregroundColor(.red).multilineTextAlignment(.center).padding(.horizontal)
                }
                
                if !bleManager.lastDebugLog.isEmpty {
                    Text(bleManager.lastDebugLog)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.secondary).lineLimit(3).padding(.horizontal)
                }
            }
            .padding(.vertical)
        }
        .alert("保存卡片转储 (Dump)", isPresented: $showDumpAlert) {
            TextField("输入转储名称", text: $dumpName)
            Button("取消", role: .cancel) {}
            Button("保存") {
                if !dumpName.isEmpty {
                    _ = mifareController.saveCurrentDump(name: dumpName)
                    dumpName = ""
                    HapticFeedback.success()
                }
            }
        } message: {
            Text("转储将保存在本机历史记录中")
        }
        .sheet(isPresented: $showWriteDumpSheet) {
            WriteDumpSheetView(mifareController: mifareController)
        }
        .sheet(isPresented: $showMagicCardSheet) {
            MagicCardView(magicController: magicController, mifareController: mifareController)
        }
        .sheet(isPresented: $showShareSheet) {
            if let url = shareURL {
                ShareSheet(items: [url])
            }
        }
        .onDisappear {
            autoDetectTimer?.invalidate()
            autoDetectTimer = nil
        }
    }
    
    // MARK: - Nested Attack Section on Home View
    private var homeNestedAttackSection: some View {
        let authedSectors = mifareController.sectors.filter { $0.isAuthenticated }
        let total = cardInfo?.totalSectors ?? 16
        let unknownCount = total - authedSectors.count
        
        return VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: "bolt.shield.fill")
                    .foregroundColor(.yellow)
                Text("已知密钥快速破解全卡 (Nested Attack)")
                    .font(.subheadline)
                    .fontWeight(.semibold)
                Spacer()
                if nestedAttack.isRunning {
                    ProgressView().tint(.yellow)
                }
            }
            
            if !authedSectors.isEmpty {
                let bestSector = authedSectors.first!
                let keyStr = bestSector.knownKey != nil ? HexUtils.bytesToHex(bestSector.knownKey!) : "未知"
                Text("基准: 扇区 \(bestSector.number) | Key \(bestSector.knownKeyType == 0x61 ? "B" : "A"): \(keyStr)")
                    .font(.caption)
                    .foregroundColor(.secondary)
            } else {
                Text("提示: 先探测或输入一个已知扇区 Key，即可利用嵌套认证算法推导其余加密扇区。")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            
            if nestedAttack.isRunning {
                VStack(spacing: 6) {
                    ProgressView(value: nestedAttack.progress)
                        .progressViewStyle(.linear)
                    HStack {
                        Text(nestedAttack.statusMessage)
                            .font(.caption2)
                            .foregroundColor(.secondary)
                        Spacer()
                        Button("停止") {
                            nestedAttack.stopAttack()
                        }
                        .font(.caption2)
                        .foregroundColor(.red)
                    }
                }
            } else {
                HStack(spacing: 10) {
                    if unknownCount > 0 && !authedSectors.isEmpty {
                        Button(action: startQuickNestedAttack) {
                            HStack {
                                Spacer()
                                Label("一键破解剩余 \(unknownCount) 个扇区", systemImage: "sparkles")
                                    .fontWeight(.medium)
                                Spacer()
                            }
                            .padding(.vertical, 10)
                            .background(Color.yellow.opacity(0.18))
                            .foregroundColor(.orange)
                            .cornerRadius(8)
                        }
                    } else if authedSectors.count == total && total > 0 {
                        HStack {
                            Image(systemName: "checkmark.seal.fill").foregroundColor(.green)
                            Text("全卡 \(total) 个扇区密钥已全部破解解密!").font(.caption).foregroundColor(.green)
                            Spacer()
                            Button("读取数据") { readFullCard() }
                                .font(.caption)
                                .foregroundColor(.blue)
                        }
                    } else {
                        Button(action: { readFullCard() }) {
                            HStack {
                                Spacer()
                                Label("先探测基础密钥 (Dump)", systemImage: "magnifyingglass")
                                    .fontWeight(.medium)
                                Spacer()
                            }
                            .padding(.vertical, 10)
                            .background(Color.blue.opacity(0.15))
                            .foregroundColor(.blue)
                            .cornerRadius(8)
                        }
                    }
                }
            }
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(12)
        .padding(.horizontal)
    }
    
    private func startQuickNestedAttack() {
        guard let card = cardInfo else { return }
        let authedSectors = mifareController.sectors.filter { $0.isAuthenticated }
        guard let baseSector = authedSectors.first, let baseKey = baseSector.knownKey else {
            errorMessage = "需先有一个已知密钥的扇区作为基准"
            HapticFeedback.error()
            return
        }
        
        let allSectorsCount = card.totalSectors
        let unknownSectorIndices = (0..<allSectorsCount).filter { idx in
            if idx < mifareController.sectors.count {
                return !mifareController.sectors[idx].isAuthenticated
            }
            return true
        }
        
        HapticFeedback.impact(.medium)
        Task {
            do {
                let recovered = try await nestedAttack.runNestedAttack(
                    knownSector: baseSector.number,
                    knownKey: baseKey,
                    knownKeyType: baseSector.knownKeyType ?? 0x60,
                    targetSectors: unknownSectorIndices
                )
                if !recovered.isEmpty {
                    HapticFeedback.success()
                }
            } catch {
                errorMessage = "嵌套攻击失败: \(error.localizedDescription)"
                HapticFeedback.error()
            }
        }
    }
    
    private func detectCard() {
        isDetecting = true
        errorMessage = nil
        HapticFeedback.impact(.light)
        Task {
            do {
                _ = try await mifareController.detectCard()
                HapticFeedback.success()
            } catch {
                errorMessage = "\(error.localizedDescription) | \(bleManager.lastDebugLog)"
                HapticFeedback.warning()
            }
            isDetecting = false
        }
    }
    
    private func readFullCard() {
        errorMessage = nil
        HapticFeedback.impact(.medium)
        Task {
            do {
                _ = try await mifareController.readAllSectors()
                HapticFeedback.success()
            } catch {
                errorMessage = "\(error.localizedDescription) | \(bleManager.lastDebugLog)"
                HapticFeedback.error()
            }
        }
    }
    
    private func saveKeysToStore() {
        let count = mifareController.saveDiscoveredKeysToStore()
        if count > 0 {
            HapticFeedback.success()
        }
    }
    
    private func exportAndShareMFD() {
        guard let card = cardInfo else { return }
        var sectorData = [Int: [UInt8]]()
        for s in mifareController.sectors {
            var fullData = [UInt8]()
            for b in s.blocks { fullData.append(contentsOf: b.data) }
            sectorData[s.number] = fullData
        }
        let atqaVal = (UInt16(card.atqa.0) << 8) | UInt16(card.atqa.1)
        let dump = MIFAREDump(
            name: "CardDump",
            date: Date(),
            uid: card.uid,
            sak: card.sak,
            atqaValue: atqaVal,
            sectors: sectorData,
            knownKeys: [:]
        )
        let bin = dump.toBinary()
        let filename = "dump_\(card.uidString.replacingOccurrences(of: ":", with: "")).mfd"
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(filename)
        do {
            try bin.write(to: url)
            shareURL = url
            showShareSheet = true
            HapticFeedback.success()
        } catch {
            errorMessage = "导出 .mfd 失败: \(error.localizedDescription)"
            HapticFeedback.error()
        }
    }
    
    private func toggleAutoDetect(_ enabled: Bool) {
        if enabled {
            autoDetectTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { _ in
                Task { @MainActor in
                    if bleManager.isConnected && !isDetecting && !mifareController.isReading {
                        detectCard()
                    }
                }
            }
        } else {
            autoDetectTimer?.invalidate()
            autoDetectTimer = nil
        }
    }
}

// MARK: - Detail Row
struct DetailRow: View {
    let label: String
    let value: String
    var body: some View {
        HStack {
            Text(label).foregroundColor(.secondary)
            Spacer()
            Text(value).fontWeight(.medium).font(.system(.body, design: .monospaced))
        }
    }
}

// MARK: - Sector List View
struct SectorListView: View {
    @ObservedObject var mifareController: MIFAREController
    @Binding var selectedSector: MIFARESector?
    
    var body: some View {
        Group {
            if mifareController.sectors.isEmpty {
                VStack(spacing: 12) {
                    Spacer()
                    Image(systemName: "square.grid.3x3").font(.system(size: 40)).foregroundColor(.gray)
                    Text("无扇区数据").foregroundColor(.gray)
                    Text("请先感应卡片并点击 Dump 读取全卡").font(.caption).foregroundColor(.secondary)
                    Spacer()
                }
            } else {
                List {
                    ForEach(mifareController.sectors) { sector in
                        SectorCell(sector: sector)
                            .contentShape(Rectangle())
                            .onTapGesture {
                                HapticFeedback.selection()
                                selectedSector = sector
                            }
                    }
                }
                .listStyle(.plain)
            }
        }
    }
}

// MARK: - Sector Cell
struct SectorCell: View {
    let sector: MIFARESector
    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("扇区 \(sector.number)").font(.headline)
                HStack(spacing: 6) {
                    Text(sector.isAuthenticated ? "已解密" : "未解密")
                        .font(.caption2)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(sector.isAuthenticated ? Color.green.opacity(0.15) : Color.red.opacity(0.15))
                        .foregroundColor(sector.isAuthenticated ? .green : .red)
                        .cornerRadius(4)
                    
                    if let type = sector.knownKeyType {
                        Text(type == 0x60 ? "Key A" : "Key B")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }
            }
            Spacer()
            if let key = sector.knownKey {
                Text(key.map { String(format: "%02X", $0) }.joined())
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.secondary)
            }
            Image(systemName: "chevron.right").foregroundColor(.gray)
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Sector Detail View
struct SectorDetailView: View {
    let sector: MIFARESector
    @ObservedObject var mifareController: MIFAREController
    @Environment(\.dismiss) var dismiss
    @State private var selectedBlock: MIFAREBlock?
    
    var body: some View {
        NavigationView {
            List {
                Section("扇区概要") {
                    DetailRow(label: "扇区编号", value: "\(sector.number)")
                    DetailRow(label: "包含数据块", value: "\(sector.blocks.count)")
                    DetailRow(label: "认证状态", value: sector.isAuthenticated ? "已解密" : "未解密")
                    if let key = sector.knownKey, let t = sector.knownKeyType {
                        DetailRow(label: "当前有效密钥 (\(t == 0x60 ? "A" : "B"))", value: HexUtils.bytesToHex(key))
                    }
                }
                
                if let abInfo = sector.accessBitsInfo {
                    Section("控制位权限解析 (Access Bits)") {
                        HStack {
                            Text("格式有效性")
                            Spacer()
                            Text(abInfo.isValid ? "正常 (取反校验通过)" : "自定义/格式异常")
                                .font(.caption)
                                .foregroundColor(abInfo.isValid ? .green : .orange)
                        }
                        VStack(alignment: .leading, spacing: 4) {
                            Text("数据块访问权限:").font(.caption).foregroundColor(.secondary)
                            ForEach(0..<min(3, abInfo.dataBlockPermissions.count), id: \.self) { i in
                                Text("块 \(sector.startBlock + i): \(abInfo.dataBlockPermissions[i])")
                                    .font(.system(size: 11, design: .monospaced))
                            }
                        }
                        VStack(alignment: .leading, spacing: 4) {
                            Text("尾块(Key/控制位)权限:").font(.caption).foregroundColor(.secondary)
                            Text(abInfo.trailerPermission)
                                .font(.system(size: 11, design: .monospaced))
                        }
                    }
                }
                
                Section("数据块列表 (点击块可单独读写)") {
                    ForEach(sector.blocks) { block in
                        BlockRow(block: block)
                            .contentShape(Rectangle())
                            .onTapGesture {
                                HapticFeedback.selection()
                                selectedBlock = block
                            }
                    }
                }
            }
            .navigationTitle("扇区 \(sector.number)")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("关闭") { dismiss() }
                }
            }
            .sheet(item: $selectedBlock) { block in
                HexEditorView(block: block, sector: sector, mifareController: mifareController)
            }
        }
    }
}

// MARK: - Block Row
struct BlockRow: View {
    let block: MIFAREBlock
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text("块 \(block.number)").font(.subheadline).fontWeight(.semibold)
                if block.isSectorTrailer {
                    Text("控制尾块 (Trailer)").font(.caption2).padding(3).background(Color.orange.opacity(0.2)).foregroundColor(.orange).cornerRadius(4)
                } else if block.number == 0 {
                    Text("厂商块 (Block 0)").font(.caption2).padding(3).background(Color.purple.opacity(0.2)).foregroundColor(.purple).cornerRadius(4)
                }
            }
            Text(block.hexString)
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.secondary)
                .lineLimit(1)
        }
        .padding(.vertical, 2)
    }
}

// MARK: - Hex Editor & Single Block Read/Write View
struct HexEditorView: View {
    let block: MIFAREBlock
    let sector: MIFARESector
    @ObservedObject var mifareController: MIFAREController
    @Environment(\.dismiss) var dismiss
    
    @State private var hexText: String
    @State private var keyHex: String
    @State private var keyType: UInt8 = 0x60
    @State private var errorMessage: String?
    @State private var successMessage: String?
    @State private var isOperating = false
    
    init(block: MIFAREBlock, sector: MIFARESector, mifareController: MIFAREController) {
        self.block = block
        self.sector = sector
        self.mifareController = mifareController
        _hexText = State(initialValue: block.data.map { String(format: "%02X", $0) }.joined(separator: " "))
        
        let initialKey = sector.knownKey != nil
            ? sector.knownKey!.map { String(format: "%02X", $0) }.joined()
            : "FFFFFFFFFFFF"
        _keyHex = State(initialValue: initialKey)
        _keyType = State(initialValue: sector.knownKeyType ?? 0x60)
    }
    
    var body: some View {
        NavigationView {
            Form {
                Section("块信息") {
                    HStack {
                        Text("位置")
                        Spacer()
                        Text("扇区 \(sector.number) - 块 \(block.number)")
                            .foregroundColor(.secondary)
                    }
                }
                
                Section("认证密钥 (用于该块的单独读写)") {
                    Picker("密钥类型", selection: $keyType) {
                        Text("Key A").tag(UInt8(0x60))
                        Text("Key B").tag(UInt8(0x61))
                    }
                    .pickerStyle(.segmented)
                    
                    TextField("6字节十六进制密钥", text: $keyHex)
                        .font(.system(.body, design: .monospaced))
                        .textInputAutocapitalization(.characters)
                        .disableAutocorrection(true)
                }
                
                Section("块数据 (16 字节十六进制)") {
                    TextEditor(text: $hexText)
                        .font(.system(.body, design: .monospaced))
                        .frame(minHeight: 80)
                }
                
                Section {
                    Button(action: readSingleBlock) {
                        HStack {
                            Spacer()
                            if isOperating { ProgressView() } else { Label("单独读取该块", systemImage: "arrow.down.doc") }
                            Spacer()
                        }
                    }
                    .disabled(isOperating)
                    
                    Button(action: writeSingleBlock) {
                        HStack {
                            Spacer()
                            Label("单独写入该块", systemImage: "arrow.up.doc.fill")
                                .foregroundColor(.red)
                            Spacer()
                        }
                    }
                    .disabled(isOperating)
                }
                
                if let msg = successMessage {
                    Section {
                        Text(msg).foregroundColor(.green).font(.caption)
                    }
                }
                if let err = errorMessage {
                    Section {
                        Text(err).foregroundColor(.red).font(.caption)
                    }
                }
            }
            .navigationTitle("单块读写 (Block \(block.number))")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("关闭") { dismiss() }
                }
            }
        }
    }
    
    private func parseCurrentKey() -> [UInt8]? {
        let clean = HexUtils.hexToBytes(keyHex.trimmingCharacters(in: .whitespacesAndNewlines))
        return clean.count == 6 ? clean : nil
    }
    
    private func readSingleBlock() {
        guard let key = parseCurrentKey() else {
            errorMessage = "密钥格式错误 (需6字节)"
            HapticFeedback.error()
            return
        }
        isOperating = true
        errorMessage = nil
        successMessage = nil
        Task {
            do {
                let data = try await mifareController.readBlockWithKey(block: block.number, key: key, keyType: keyType)
                hexText = data.map { String(format: "%02X", $0) }.joined(separator: " ")
                successMessage = "读取成功!"
                HapticFeedback.success()
            } catch {
                errorMessage = "读取失败: \(error.localizedDescription)"
                HapticFeedback.error()
            }
            isOperating = false
        }
    }
    
    private func writeSingleBlock() {
        guard let key = parseCurrentKey() else {
            errorMessage = "密钥格式错误 (需6字节)"
            HapticFeedback.error()
            return
        }
        let cleanData = HexUtils.hexToBytes(hexText.trimmingCharacters(in: .whitespacesAndNewlines))
        guard cleanData.count == 16 else {
            errorMessage = "数据必须为 16 字节十六进制"
            HapticFeedback.error()
            return
        }
        isOperating = true
        errorMessage = nil
        successMessage = nil
        Task {
            do {
                let ok = try await mifareController.writeBlockWithKey(block: block.number, data: cleanData, key: key, keyType: keyType)
                if ok {
                    successMessage = "写入成功!"
                    HapticFeedback.success()
                } else {
                    errorMessage = "写入未成功"
                    HapticFeedback.error()
                }
            } catch {
                errorMessage = "写入失败: \(error.localizedDescription)"
                HapticFeedback.error()
            }
            isOperating = false
        }
    }
}

// MARK: - Write Dump Sheet View
struct WriteDumpSheetView: View {
    @ObservedObject var mifareController: MIFAREController
    @Environment(\.dismiss) var dismiss
    @State private var isWriting = false
    @State private var resultMessage: String?
    
    var body: some View {
        NavigationView {
            VStack {
                if mifareController.dumpHistory.isEmpty {
                    VStack(spacing: 12) {
                        Spacer()
                        Image(systemName: "tray").font(.system(size: 40)).foregroundColor(.gray)
                        Text("无可用 Dump 备份").foregroundColor(.gray)
                        Text("请先通过 Dump 按钮读取并保存卡片数据").font(.caption).foregroundColor(.secondary)
                        Spacer()
                    }
                } else {
                    List(mifareController.dumpHistory) { dump in
                        VStack(alignment: .leading, spacing: 6) {
                            HStack {
                                Text(dump.name).font(.headline)
                                Spacer()
                                Text(dump.formattedDate).font(.caption).foregroundColor(.secondary)
                            }
                            Text("UID: \(dump.uidString) | \(dump.sectors.count) 个扇区")
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(.secondary)
                            
                            Button(action: { writeDump(dump) }) {
                                HStack {
                                    Spacer()
                                    Text("回写此 Dump 到当前卡片")
                                        .font(.subheadline)
                                        .fontWeight(.semibold)
                                    Spacer()
                                }
                                .padding(.vertical, 8)
                                .background(Color.purple.opacity(0.15))
                                .foregroundColor(.purple)
                                .cornerRadius(8)
                            }
                            .disabled(isWriting)
                        }
                        .padding(.vertical, 4)
                    }
                }
                
                if isWriting {
                    VStack(spacing: 6) {
                        ProgressView(value: mifareController.progress)
                        Text(mifareController.statusMessage)
                            .font(.caption).foregroundColor(.secondary)
                    }
                    .padding()
                }
                
                if let msg = resultMessage {
                    Text(msg)
                        .font(.caption)
                        .padding()
                }
            }
            .navigationTitle("回写 Dump 到卡片")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("取消") { dismiss() }
                }
            }
        }
    }
    
    private func writeDump(_ dump: MIFAREDump) {
        isWriting = true
        resultMessage = nil
        Task {
            do {
                let res = try await mifareController.writeDumpToCard(dump)
                resultMessage = "写入结果: 成功 \(res.written) 个扇区，失败 \(res.failed) 个扇区"
                if res.failed == 0 {
                    HapticFeedback.success()
                } else {
                    HapticFeedback.warning()
                }
            } catch {
                resultMessage = "写入失败: \(error.localizedDescription)"
                HapticFeedback.error()
            }
            isWriting = false
        }
    }
}

// MARK: - Quick Action Button
struct QuickActionButton: View {
    let title: String
    let color: Color
    let action: () -> Void
    
    init(_ title: String, color: Color, action: @escaping () -> Void) {
        self.title = title
        self.color = color
        self.action = action
    }
    
    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.caption)
                .fontWeight(.medium)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)
                .background(color.opacity(0.15))
                .foregroundColor(color)
                .cornerRadius(8)
        }
    }
}
