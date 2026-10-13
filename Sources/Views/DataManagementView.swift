import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

// MARK: - Data Management View (Tab 3: 数据)
struct DataManagementView: View {
    @ObservedObject var mifareController: MIFAREController
    @ObservedObject var keyStore: KeyStore
    @ObservedObject var bleManager: BLEManager
    
    @State private var selectedSegment = 0 // 0: Dumps, 1: Keys
    @State private var searchKeyText = ""
    @State private var showAddKeySheet = false
    @State private var newKeyLabel = ""
    @State private var newKeyHex = ""
    @State private var addKeyError: String?
    
    @State private var selectedDumpForDetail: MIFAREDump?
    @State private var selectedDumpForWrite: MIFAREDump?
    @State private var showWriteDumpAlert = false
    @State private var isWritingDump = false
    @State private var writeDumpStatus: String?
    
    @State private var shareURL: URL?
    @State private var showShareSheet = false
    @State private var showFileImporter = false
    
    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                // Top Segment Picker
                Picker("数据类型", selection: $selectedSegment) {
                    Text("卡片转储 (Dumps)").tag(0)
                    Text("密钥库 (Keys)").tag(1)
                }
                .pickerStyle(.segmented)
                .padding()
                
                if selectedSegment == 0 {
                    dumpListView
                } else {
                    keyListView
                }
            }
            .navigationTitle("数据管理")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    if selectedSegment == 0 {
                        Button(action: { showFileImporter = true }) {
                            Image(systemName: "square.and.arrow.down")
                        }
                    } else {
                        Button(action: { showAddKeySheet = true }) {
                            Image(systemName: "plus")
                        }
                    }
                }
            }
            .sheet(item: $selectedDumpForDetail) { dump in
                DataDumpDetailView(dump: dump, mifareController: mifareController)
            }
            .sheet(isPresented: $showShareSheet) {
                if let url = shareURL {
                    ShareSheet(items: [url])
                }
            }
            .sheet(isPresented: $showAddKeySheet) {
                addKeySheetView
            }
            .fileImporter(
                isPresented: $showFileImporter,
                allowedContentTypes: [.data],
                allowsMultipleSelection: false
            ) { result in
                handleImportFile(result)
            }
            .alert("回写 Dump 到卡片", isPresented: $showWriteDumpAlert) {
                Button("取消", role: .cancel) {}
                Button("开始写入", role: .destructive) {
                    if let d = selectedDumpForWrite {
                        performWriteDump(d)
                    }
                }
            } message: {
                if let d = selectedDumpForWrite {
                    Text("确定将 '\(d.name)' 的数据写入当前贴近读卡器的卡片吗？此操作将覆盖卡片数据。")
                } else {
                    Text("确定写入卡片吗？")
                }
            }
        }
    }
    
    // MARK: - Dump List Section
    private var dumpListView: some View {
        Group {
            if mifareController.dumpHistory.isEmpty {
                VStack(spacing: 16) {
                    Spacer()
                    Image(systemName: "tray")
                        .font(.system(size: 50))
                        .foregroundColor(.gray)
                    Text("暂无保存的 Dump 数据")
                        .font(.headline)
                        .foregroundColor(.gray)
                    Text("您可以在首页检测卡片后点击 'Dump' 进行全卡读取并保存")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 40)
                    Spacer()
                }
            } else {
                List {
                    ForEach(mifareController.dumpHistory) { dump in
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Text(dump.name)
                                    .font(.headline)
                                Spacer()
                                Text(dump.formattedDate)
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            
                            HStack(spacing: 12) {
                                Label(dump.uidString, systemImage: "creditcard")
                                    .font(.system(size: 11, design: .monospaced))
                                    .foregroundColor(.secondary)
                                
                                Label("\(dump.sectors.count) 扇区", systemImage: "square.grid.3x3")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            
                            HStack(spacing: 10) {
                                Button(action: { selectedDumpForDetail = dump }) {
                                    Label("查看详情", systemImage: "eye")
                                        .font(.caption)
                                        .padding(.horizontal, 10)
                                        .padding(.vertical, 6)
                                        .background(Color.blue.opacity(0.12))
                                        .foregroundColor(.blue)
                                        .cornerRadius(6)
                                }
                                
                                Button(action: {
                                    selectedDumpForWrite = dump
                                    showWriteDumpAlert = true
                                }) {
                                    Label("写入卡片", systemImage: "square.and.arrow.up")
                                        .font(.caption)
                                        .padding(.horizontal, 10)
                                        .padding(.vertical, 6)
                                        .background(Color.purple.opacity(0.12))
                                        .foregroundColor(.purple)
                                        .cornerRadius(6)
                                }
                                .disabled(!bleManager.isConnected || mifareController.isReading)
                                
                                Button(action: { shareDumpMFD(dump) }) {
                                    Label("导出.mfd", systemImage: "square.and.arrow.up.on.square")
                                        .font(.caption)
                                        .padding(.horizontal, 10)
                                        .padding(.vertical, 6)
                                        .background(Color.green.opacity(0.12))
                                        .foregroundColor(.green)
                                        .cornerRadius(6)
                                }
                            }
                            .padding(.top, 2)
                        }
                        .padding(.vertical, 4)
                    }
                    .onDelete(perform: deleteDumps)
                }
                .listStyle(.insetGrouped)
            }
            
            if isWritingDump {
                VStack(spacing: 6) {
                    ProgressView(value: mifareController.progress)
                    Text(mifareController.statusMessage)
                        .font(.caption).foregroundColor(.secondary)
                }
                .padding()
            } else if let status = writeDumpStatus {
                Text(status)
                    .font(.caption)
                    .padding(.horizontal)
                    .padding(.bottom, 8)
            }
        }
    }
    
    // MARK: - Key List Section
    private var filteredKeys: [(String, [UInt8])] {
        let all = keyStore.savedKeys
        if searchKeyText.isEmpty { return all }
        let q = searchKeyText.lowercased()
        return all.filter {
            $0.0.lowercased().contains(q) ||
            HexUtils.bytesToHex($0.1).lowercased().contains(q)
        }
    }
    
    private var keyListView: some View {
        VStack(spacing: 0) {
            // Search Bar
            HStack {
                Image(systemName: "magnifyingglass").foregroundColor(.gray)
                TextField("搜索密钥标签或十六进制", text: $searchKeyText)
                    .textFieldStyle(.plain)
                if !searchKeyText.isEmpty {
                    Button(action: { searchKeyText = "" }) {
                        Image(systemName: "xmark.circle.fill").foregroundColor(.gray)
                    }
                }
            }
            .padding(8)
            .background(Color(.systemGray6))
            .cornerRadius(8)
            .padding(.horizontal)
            .padding(.vertical, 6)
            
            List {
                Section("本地密钥库 (\(filteredKeys.count))") {
                    if filteredKeys.isEmpty {
                        Text("无匹配的密钥记录").foregroundColor(.secondary)
                    } else {
                        ForEach(Array(filteredKeys.enumerated()), id: \.offset) { idx, item in
                            HStack {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(item.0).font(.subheadline).fontWeight(.medium)
                                    Text(HexUtils.bytesToHex(item.1))
                                        .font(.system(size: 13, design: .monospaced))
                                        .foregroundColor(.secondary)
                                }
                                Spacer()
                                Button(action: {
                                    UIPasteboard.general.string = HexUtils.bytesToHex(item.1).replacingOccurrences(of: " ", with: "")
                                    HapticFeedback.selection()
                                }) {
                                    Image(systemName: "doc.on.doc").foregroundColor(.blue)
                                }
                            }
                            .padding(.vertical, 2)
                        }
                        .onDelete(perform: deleteKeyAtIndex)
                    }
                }
                
                Section("系统出厂常见默认密钥参考") {
                    ForEach(MIFAREKeyManager.defaultKeys, id: \.self) { defKey in
                        HStack {
                            Text(HexUtils.bytesToHex(defKey))
                                .font(.system(size: 12, design: .monospaced))
                                .foregroundColor(.secondary)
                            Spacer()
                            Button("添加到库") {
                                if keyStore.saveKeyIfNotExists(label: "默认密钥", key: defKey) {
                                    HapticFeedback.success()
                                } else {
                                    HapticFeedback.warning()
                                }
                            }
                            .font(.caption)
                        }
                    }
                }
            }
            .listStyle(.insetGrouped)
        }
    }
    
    // MARK: - Add Key Sheet View
    private var addKeySheetView: some View {
        NavigationView {
            Form {
                Section("密钥信息") {
                    TextField("标签名称 (如: 门禁卡-扇区0)", text: $newKeyLabel)
                    TextField("6字节十六进制 (如: FFFFFFFFFFFF)", text: $newKeyHex)
                        .font(.system(.body, design: .monospaced))
                        .textInputAutocapitalization(.characters)
                        .disableAutocorrection(true)
                }
                
                if let err = addKeyError {
                    Section {
                        Text(err).foregroundColor(.red).font(.caption)
                    }
                }
                
                Section {
                    Button(action: saveCustomKey) {
                        HStack {
                            Spacer()
                            Text("保存到密钥库").fontWeight(.semibold)
                            Spacer()
                        }
                    }
                }
            }
            .navigationTitle("添加密钥")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("取消") { showAddKeySheet = false }
                }
            }
        }
    }
    
    private func saveCustomKey() {
        let cleanHex = newKeyHex.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let bytes = UInt8.hexToBytes(cleanHex), bytes.count == 6 else {
            addKeyError = "请输入正确的 6 字节十六进制密钥 (12个字符)"
            HapticFeedback.error()
            return
        }
        let label = newKeyLabel.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "自定义密钥" : newKeyLabel
        keyStore.saveKey(label: label, key: bytes)
        HapticFeedback.success()
        newKeyLabel = ""
        newKeyHex = ""
        addKeyError = nil
        showAddKeySheet = false
    }
    
    private func deleteDumps(at offsets: IndexSet) {
        mifareController.dumpHistory.remove(atOffsets: offsets)
        mifareController.saveDumpsToDisk()
        HapticFeedback.selection()
    }
    
    private func deleteKeyAtIndex(at offsets: IndexSet) {
        for index in offsets {
            keyStore.deleteKey(at: index)
        }
        HapticFeedback.selection()
    }
    
    private func shareDumpMFD(_ dump: MIFAREDump) {
        let bin = dump.toBinary()
        let filename = "\(dump.name.replacingOccurrences(of: " ", with: "_"))_\(dump.uidString.replacingOccurrences(of: ":", with: "")).mfd"
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(filename)
        do {
            try bin.write(to: url)
            shareURL = url
            showShareSheet = true
            HapticFeedback.success()
        } catch {
            writeDumpStatus = "导出失败: \(error.localizedDescription)"
            HapticFeedback.error()
        }
    }
    
    private func performWriteDump(_ dump: MIFAREDump) {
        isWritingDump = true
        writeDumpStatus = nil
        Task {
            do {
                let res = try await mifareController.writeDumpToCard(dump)
                writeDumpStatus = "写入结果: 成功 \(res.written) 个扇区，失败 \(res.failed) 个扇区"
                if res.failed == 0 {
                    HapticFeedback.success()
                } else {
                    HapticFeedback.warning()
                }
            } catch {
                writeDumpStatus = "写入失败: \(error.localizedDescription)"
                HapticFeedback.error()
            }
            isWritingDump = false
        }
    }
    
    private func handleImportFile(_ result: Result<[URL], Error>) {
        do {
            guard let selectedFile = try result.get().first else { return }
            if selectedFile.startAccessingSecurityScopedResource() {
                defer { selectedFile.stopAccessingSecurityScopedResource() }
                let data = try Data(contentsOf: selectedFile)
                let name = selectedFile.deletingPathExtension().lastPathComponent
                if let importedDump = mifareController.importDumpFromBinary(data, name: name) {
                    mifareController.dumpHistory.append(importedDump)
                    mifareController.saveDumpsToDisk()
                    writeDumpStatus = "成功导入 Dump: \(name) (\(importedDump.sectors.count) 个扇区)"
                    HapticFeedback.success()
                } else {
                    writeDumpStatus = "文件格式不匹配 (需为标准 1024 字节或 4096 字节 .mfd)"
                    HapticFeedback.error()
                }
            }
        } catch {
            writeDumpStatus = "导入失败: \(error.localizedDescription)"
            HapticFeedback.error()
        }
    }
}

// MARK: - Dump Detail View (Data Tab)
struct DataDumpDetailView: View {
    let dump: MIFAREDump
    @ObservedObject var mifareController: MIFAREController
    @Environment(\.dismiss) var dismiss
    
    var body: some View {
        NavigationView {
            List {
                Section("转储基本信息") {
                    DetailRow(label: "名称", value: dump.name)
                    DetailRow(label: "UID", value: dump.uidString)
                    DetailRow(label: "SAK", value: String(format: "0x%02X", dump.sak))
                    DetailRow(label: "ATQA", value: String(format: "0x%04X", dump.atqaValue))
                    DetailRow(label: "保存日期", value: dump.formattedDate)
                    DetailRow(label: "总扇区数", value: "\(dump.sectors.count)")
                }
                
                Section("扇区数据明细 (\(dump.sectors.count) 扇区)") {
                    ForEach(dump.sectors.sorted(by: { $0.key < $1.key }), id: \.key) { sectorNum, sectorData in
                        VStack(alignment: .leading, spacing: 6) {
                            HStack {
                                Text("扇区 \(sectorNum)").font(.headline)
                                Spacer()
                                if let keyEntry = dump.knownKeys[sectorNum] {
                                    Text("Key \(keyEntry.keyType == 0x61 ? "B" : "A"): \(HexUtils.bytesToHex(keyEntry.keyData))")
                                        .font(.system(size: 11, design: .monospaced))
                                        .foregroundColor(.green)
                                }
                            }
                            
                            // Blocks in sector
                            let blockCount = sectorNum < 32 ? 4 : 16
                            let startBlock = sectorNum < 32 ? sectorNum * 4 : 128 + (sectorNum - 32) * 16
                            
                            ForEach(0..<blockCount, id: \.self) { b in
                                let currentBlockNum = startBlock + b
                                let bOffset = b * 16
                                if bOffset + 16 <= sectorData.count {
                                    let bData = Array(sectorData[bOffset..<bOffset + 16])
                                    HStack {
                                        Text("B\(currentBlockNum):")
                                            .font(.system(size: 10, design: .monospaced))
                                            .foregroundColor(.secondary)
                                            .frame(width: 32, alignment: .leading)
                                        Text(HexUtils.bytesToHex(bData))
                                            .font(.system(size: 10, design: .monospaced))
                                            .foregroundColor(.primary)
                                            .lineLimit(1)
                                    }
                                }
                            }
                        }
                        .padding(.vertical, 4)
                    }
                }
            }
            .navigationTitle(dump.name)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("关闭") { dismiss() }
                }
            }
        }
    }
}
