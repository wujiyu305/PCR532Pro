import SwiftUI

// MARK: - Key Manager View
struct KeyManagerView: View {
    @ObservedObject var keyStore: KeyStore
    @ObservedObject var mifareController: MIFAREController
    @ObservedObject var dictionaryAttack: DictionaryAttack
    @ObservedObject var nestedAttack: NestedAttack
    @ObservedObject var darkSideAttack: DarkSideAttack
    @ObservedObject var bleManager: BLEManager
    @State private var showAddKey = false
    @State private var newKeyLabel = ""
    @State private var newKeyHex = ""
    @State private var keyError: String?
    @State private var showDictionaryAttack = false
    @State private var showNestedAttack = false
    @State private var showDarkSideAttack = false
    
    var body: some View {
        NavigationView {
            List {
                // Section: Default keys
                Section("默认密钥字典 (\(MIFAREKeyManager.defaultKeys.count) 个)") {
                    ForEach(0..<min(MIFAREKeyManager.defaultKeysDescription.count, 8), id: \.self) { i in
                        let (name, key) = MIFAREKeyManager.defaultKeysDescription[i]
                        HStack {
                            Text(name)
                                .font(.subheadline)
                            Spacer()
                            Text(key.map { String(format: "%02X", $0) }.joined(separator: " "))
                                .font(.system(.caption, design: .monospaced))
                                .foregroundColor(.blue)
                        }
                    }
                    
                    if MIFAREKeyManager.defaultKeys.count > 8 {
                        DisclosureGroup("展开全部 \(MIFAREKeyManager.defaultKeys.count) 个") {
                            ForEach(8..<MIFAREKeyManager.defaultKeys.count, id: \.self) { i in
                                HStack {
                                    Text("密钥 \(i + 1)")
                                        .font(.subheadline)
                                    Spacer()
                                    Text(MIFAREKeyManager.defaultKeys[i].map { String(format: "%02X", $0) }.joined(separator: " "))
                                        .font(.system(.caption, design: .monospaced))
                                        .foregroundColor(.blue)
                                }
                            }
                        }
                    }
                }
                
                // Section: Custom keys
                Section("自定义密钥 (\(keyStore.savedKeys.count) 个)") {
                    if keyStore.savedKeys.isEmpty {
                        Text("暂无自定义密钥，点击右上角 + 添加")
                            .font(.caption)
                            .foregroundColor(.gray)
                    }
                    
                    ForEach(Array(keyStore.savedKeys.enumerated()), id: \.offset) { index, keyItem in
                        HStack {
                            Text(keyItem.0)
                                .font(.subheadline)
                            Spacer()
                            Text(keyItem.1.map { String(format: "%02X", $0) }.joined(separator: " "))
                                .font(.system(.caption, design: .monospaced))
                                .foregroundColor(.green)
                        }
                    }
                    .onDelete { indexSet in
                        for index in indexSet {
                            keyStore.deleteKey(at: index)
                        }
                    }
                }
                
                // Section: Dictionary Attack
                Section("字典攻击") {
                    if dictionaryAttack.isRunning {
                        VStack(spacing: 8) {
                            ProgressView(value: dictionaryAttack.progress)
                                .progressViewStyle(.linear)
                            Text(dictionaryAttack.statusMessage)
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        .padding(.vertical, 4)
                    } else {
                        Button(action: { showDictionaryAttack = true }) {
                            HStack {
                                Image(systemName: "book.fill")
                                Text("运行字典攻击")
                            }
                        }
                        
                        if !dictionaryAttack.foundKeys.isEmpty {
                            Text("已发现 \(dictionaryAttack.foundKeys.count) 个扇区密钥")
                                .font(.caption)
                                .foregroundColor(.green)
                        }
                    }
                }
                
                // Section: Nested Attack
                Section("嵌套攻击") {
                    Button(action: { showNestedAttack = true }) {
                        HStack {
                            Image(systemName: "arrow.triangle.branch")
                            Text("从已知密钥破解其它扇区")
                        }
                    }
                    .disabled(mifareController.sectors.filter { $0.isAuthenticated }.isEmpty)
                    
                    if mifareController.sectors.filter({ $0.isAuthenticated }).isEmpty {
                        Text("需要先读取至少一个扇区获取已知密钥")
                            .font(.caption)
                            .foregroundColor(.gray)
                    }
                }
                
                // Section: DarkSide Attack
                Section("暗侧攻击 (零知识)") {
                    Button(action: { showDarkSideAttack = true }) {
                        HStack {
                            Image(systemName: "moon.fill")
                            Text("零知识密钥恢复")
                        }
                    }
                    
                    Text("不需要任何已知密钥，通过分析加密响应恢复密钥")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                
                // Section: Attack results
                if !dictionaryAttack.foundKeys.isEmpty {
                    Section("攻击结果") {
                        ForEach(Array(dictionaryAttack.foundKeys.sorted(by: { $0.key < $1.key })), id: \.key) { sector, keyInfo in
                            HStack {
                                Text("扇区 \(sector)")
                                    .font(.subheadline)
                                Spacer()
                                Text(keyInfo.key.map { String(format: "%02X", $0) }.joined(separator: " "))
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundColor(.green)
                                Text(keyInfo.type == 0x60 ? "A" : "B")
                                    .font(.caption)
                                    .foregroundColor(.blue)
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(Color.blue.opacity(0.1))
                                    .cornerRadius(4)
                            }
                        }
                    }
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("密钥管理")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: { showAddKey = true }) {
                        Image(systemName: "plus")
                    }
                }
            }
            .sheet(isPresented: $showAddKey) {
                addKeySheet
            }
            .sheet(isPresented: $showDictionaryAttack) {
                attackConfigSheet
            }
            .sheet(isPresented: $showNestedAttack) {
                NavigationView {
                    NestedAttackConfigView(
                        nestedAttack: nestedAttack,
                        mifareController: mifareController
                    )
                }
            }
            .sheet(isPresented: $showDarkSideAttack) {
                NavigationView {
                    DarkSideAttackConfigView(
                        darkSideAttack: darkSideAttack,
                        mifareController: mifareController
                    )
                }
            }
        }
    }
    
    // MARK: - Add Key Sheet
    private var addKeySheet: some View {
        NavigationView {
            Form {
                Section("Add custom key") {
                    TextField("Key name", text: $newKeyLabel)
                    TextField("6-byte hex e.g. FFFFFFFFFFFF", text: $newKeyHex)
                        .font(.system(.body, design: .monospaced))
                        .textInputAutocapitalization(.characters)
                    
                    if let error = keyError {
                        Text(error)
                            .font(.caption)
                            .foregroundColor(.red)
                    }
                    
                    // Quick add buttons
                    HStack {
                        QuickActionButton("FF FF FF FF FF FF", color: .blue) {
                            newKeyHex = "FFFFFFFFFFFF"
                        }
                        QuickActionButton("00 00 00 00 00 00", color: .orange) {
                            newKeyHex = "000000000000"
                        }
                        QuickActionButton("A0A1A2A3A4A5", color: .green) {
                            newKeyHex = "A0A1A2A3A4A5"
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
            .navigationTitle("Add Key")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("取消") { showAddKey = false }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("保存") { addKey() }
                        .disabled(newKeyLabel.isEmpty || newKeyHex.isEmpty)
                }
            }
        }
    }
    
    private func addKey() {
        let cleaned = newKeyHex.replacingOccurrences(of: " ", with: "")
        guard let bytes = UInt8.hexToBytes(cleaned), bytes.count == 6 else {
            keyError = "请输入有效的6字节十六进制密钥"
            return
        }
        keyStore.saveKey(label: newKeyLabel, key: bytes)
        newKeyLabel = ""
        newKeyHex = ""
        keyError = nil
        showAddKey = false
    }
    
    // MARK: - Attack Config Sheet
    private var attackConfigSheet: some View {
        NavigationView {
            AttackConfigView(
                mifareController: mifareController,
                dictionaryAttack: dictionaryAttack
            )
        }
    }
}

// MARK: - Attack Config View
struct AttackConfigView: View {
    @ObservedObject var mifareController: MIFAREController
    @ObservedObject var dictionaryAttack: DictionaryAttack
    @Environment(\.dismiss) var dismiss
    @State private var totalSectors = 16
    
    var body: some View {
        VStack(spacing: 20) {
            if dictionaryAttack.isRunning {
                VStack(spacing: 12) {
                    ProgressView()
                        .scaleEffect(1.5)
                    Text("字典攻击进行中...")
                        .font(.headline)
                    ProgressView(value: dictionaryAttack.progress)
                        .progressViewStyle(.linear)
                        .padding(.horizontal)
                    Text(dictionaryAttack.statusMessage)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .padding()
            } else {
                // Config
                VStack(alignment: .leading, spacing: 16) {
                    Text("字典攻击配置")
                        .font(.title2)
                        .fontWeight(.bold)
                    
                    Text("尝试所有已知默认密钥对每个扇区进行认证。")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                    
                    HStack {
                        Text("目标扇区数:")
                        Spacer()
                        Picker("", selection: $totalSectors) {
                            Text("16 (1K)").tag(16)
                            Text("40 (4K)").tag(40)
                        }
                        .pickerStyle(.segmented)
                        .frame(width: 160)
                    }
                    
                    Divider()
                    
                    VStack(alignment: .leading, spacing: 8) {
                        Text("将尝试:")
                            .font(.subheadline)
                        Text("• \(MIFAREKeyManager.defaultKeys.count) 个默认密钥 × 2 种密钥类型")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text("• \(totalSectors) 个扇区")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text("• 总计约 \(totalSectors * 2 * MIFAREKeyManager.defaultKeys.count) 次认证尝试")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text("⚠️ 请确保卡片已放置好，整个过程可能需要1-5分钟")
                            .font(.caption)
                            .foregroundColor(.orange)
                    }
                }
                .padding()
                
                Spacer()
                
                Button(action: { startAttack() }) {
                    Text("开始字典攻击")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.blue)
                        .foregroundColor(.white)
                        .cornerRadius(12)
                }
                .padding()
            }
        }
        .navigationTitle("字典攻击")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarLeading) {
                if !dictionaryAttack.isRunning {
                    Button("取消") { dismiss() }
                }
            }
        }
    }
    
    private func startAttack() {
        Task {
            do {
                _ = try await dictionaryAttack.run(totalSectors: totalSectors)
            } catch {
                // Attack error handled in ViewModel
            }
            dismiss()
        }
    }
}

// MARK: - Key Detail Row
struct KeyDetailRow: View {
    let label: String
    let key: [UInt8]?
    
    var body: some View {
        HStack {
            Text(label)
                .font(.subheadline)
                .foregroundColor(.secondary)
            Spacer()
            if let key = key {
                Text(HexUtils.bytesToHex(key))
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(key == [UInt8](repeating: 0xFF, count: 6) || key == [UInt8](repeating: 0x00, count: 6)
                        ? .orange : .green)
            } else {
                Text("未知")
                    .font(.caption)
                    .foregroundColor(.red)
            }
        }
    }
}