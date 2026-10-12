import SwiftUI

// MARK: - Nested Attack View
struct NestedAttackConfigView: View {
    @ObservedObject var nestedAttack: NestedAttack
    @ObservedObject var mifareController: MIFAREController
    @Environment(\.dismiss) var dismiss
    
    @State private var knownSector = 0
    @State private var targetSectorRange: ClosedRange<Int> = 1...15
    @State private var knownKeyHex = ""
    
    var body: some View {
        VStack(spacing: 16) {
            if nestedAttack.isRunning {
                VStack(spacing: 12) {
                    ProgressView()
                        .scaleEffect(1.5)
                    Text("嵌套攻击进行中...")
                        .font(.headline)
                    ProgressView(value: nestedAttack.progress)
                        .progressViewStyle(.linear)
                        .padding(.horizontal)
                    Text(nestedAttack.statusMessage)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .padding()
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 20) {
                        // Info
                        VStack(alignment: .leading, spacing: 8) {
                            Text("嵌套攻击说明")
                                .font(.headline)
                            Text("当已知某个扇区的密钥时，利用它来破解其他未知扇区的密钥。算法基于 Crypto1 加密分析的 LFSR 状态恢复。")
                                .font(.subheadline)
                                .foregroundColor(.secondary)
                        }
                        .padding()
                        .background(Color.blue.opacity(0.05))
                        .cornerRadius(12)
                        
                        // Known sector
                        GroupBox(label: Text("已知密钥扇区").font(.headline)) {
                            VStack(spacing: 12) {
                                HStack {
                                    Text("扇区号:")
                                    Picker("", selection: $knownSector) {
                                        ForEach(0..<40, id: \.self) { i in
                                            Text("S\(i)").tag(i)
                                        }
                                    }
                                }
                                
                                HStack {
                                    Text("密钥 (6字节十六进制):")
                                    TextField("FFFFFFFFFFFF", text: $knownKeyHex)
                                        .font(.system(.body, design: .monospaced))
                                        .textInputAutocapitalization(.characters)
                                }
                                
                                if let knownKey = mifareController.sectors.first(where: { $0.number == knownSector })?.knownKey {
                                    Text("从已读数据获取: \(knownKey.map { String(format: "%02X", $0) }.joined())")
                                        .font(.caption)
                                        .foregroundColor(.green)
                                }
                            }
                            .padding(.vertical, 4)
                        }
                        
                        // Target sectors
                        GroupBox(label: Text("目标扇区").font(.headline)) {
                            VStack(spacing: 12) {
                                Stepper("开始扇区: \(targetSectorRange.lowerBound)", value: Binding(
                                    get: { targetSectorRange.lowerBound },
                                    set: { targetSectorRange = $0...targetSectorRange.upperBound }
                                ), in: 0...39)
                                
                                Stepper("结束扇区: \(targetSectorRange.upperBound)", value: Binding(
                                    get: { targetSectorRange.upperBound },
                                    set: { targetSectorRange = targetSectorRange.lowerBound...$0 }
                                ), in: targetSectorRange.lowerBound...39)
                                
                                Text("目标: \(targetSectorRange.upperBound - targetSectorRange.lowerBound + 1) 个扇区")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            .padding(.vertical, 4)
                        }
                        
                        // Warning
                        HStack {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundColor(.orange)
                            Text("嵌套攻击需要较强的计算能力，破解过程可能需要 1-5 分钟")
                                .font(.caption)
                                .foregroundColor(.orange)
                        }
                        .padding(.horizontal)
                    }
                    .padding()
                }
                
                Spacer()
                
                Button(action: { startNestedAttack() }) {
                    Text("开始嵌套攻击")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(isValid ? Color.blue : Color.gray)
                        .foregroundColor(.white)
                        .cornerRadius(12)
                }
                .disabled(!isValid)
                .padding()
            }
        }
        .navigationTitle("嵌套攻击")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarLeading) {
                if !nestedAttack.isRunning {
                    Button("取消") { dismiss() }
                }
            }
        }
    }
    
    private var isValid: Bool {
        if !knownKeyHex.isEmpty {
            return HexUtils.isValidHex(knownKeyHex) && knownKeyHex.replacingOccurrences(of: " ", with: "").count == 12
        }
        return mifareController.sectors.first(where: { $0.number == knownSector && $0.isAuthenticated }) != nil
    }
    
    private func startNestedAttack() {
        let key: [UInt8]
        let keyType: UInt8
        
        if !knownKeyHex.isEmpty {
            key = HexUtils.hexToBytes(knownKeyHex)
            keyType = 0x60
        } else if let sector = mifareController.sectors.first(where: { $0.number == knownSector && $0.isAuthenticated }),
                  let known = sector.knownKey {
            key = known
            keyType = sector.knownKeyType ?? 0x60
        } else {
            return
        }
        
        let targets = Array(targetSectorRange.lowerBound...targetSectorRange.upperBound)
        
        Task {
            do {
                _ = try await nestedAttack.runNestedAttack(
                    knownSector: knownSector,
                    knownKey: key,
                    knownKeyType: keyType,
                    targetSectors: targets
                )
            } catch {
                // Handled in NestedAttack state
            }
            dismiss()
        }
    }
}

// MARK: - DarkSide Attack View
struct DarkSideAttackConfigView: View {
    @ObservedObject var darkSideAttack: DarkSideAttack
    @ObservedObject var mifareController: MIFAREController
    @Environment(\.dismiss) var dismiss
    
    @State private var targetSector = 0
    @State private var useKeyA = true
    
    var body: some View {
        VStack(spacing: 16) {
            if darkSideAttack.isRunning {
                VStack(spacing: 12) {
                    ProgressView()
                        .scaleEffect(1.5)
                    Text("暗侧攻击进行中...")
                        .font(.headline)
                    ProgressView(value: darkSideAttack.progress)
                        .progressViewStyle(.linear)
                        .padding(.horizontal)
                    Text(darkSideAttack.statusMessage)
                        .font(.caption)
                        .foregroundColor(.secondary)
                    
                    if darkSideAttack.foundKey != nil {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundColor(.green)
                            .font(.system(size: 40))
                    }
                }
                .padding()
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 20) {
                        // Info
                        VStack(alignment: .leading, spacing: 8) {
                            Text("暗侧攻击 (DarkSide)")
                                .font(.headline)
                            Text("零知识攻击，不需要任何已知密钥。通过发送数百次错误认证请求，分析卡片的加密响应来恢复密钥。")
                                .font(.subheadline)
                                .foregroundColor(.secondary)
                            Text("适用场景: 卡片所有扇区密钥均未知，且默认字典攻击失败时")
                                .font(.caption)
                                .foregroundColor(.orange)
                        }
                        .padding()
                        .background(Color.purple.opacity(0.05))
                        .cornerRadius(12)
                        
                        // Target
                        GroupBox(label: Text("目标扇区").font(.headline)) {
                            VStack(spacing: 12) {
                                HStack {
                                    Text("扇区号:")
                                    Picker("", selection: $targetSector) {
                                        ForEach(0..<40, id: \.self) { i in
                                            Text("S\(i)").tag(i)
                                        }
                                    }
                                }
                                
                                Toggle("使用密钥 A (否则密钥 B)", isOn: $useKeyA)
                                    .font(.subheadline)
                            }
                            .padding(.vertical, 4)
                        }
                        
                        // Stats
                        GroupBox(label: Text("攻击说明").font(.headline)) {
                            VStack(alignment: .leading, spacing: 8) {
                                HStack {
                                    Image(systemName: "1.circle.fill")
                                        .foregroundColor(.purple)
                                    Text("发送约 500 次随机认证请求")
                                        .font(.caption)
                                }
                                HStack {
                                    Image(systemName: "2.circle.fill")
                                        .foregroundColor(.purple)
                                    Text("收集加密随机数响应")
                                        .font(.caption)
                                }
                                HStack {
                                    Image(systemName: "3.circle.fill")
                                        .foregroundColor(.purple)
                                    Text("统计分析恢复 Crypto1 LFSR 状态")
                                        .font(.caption)
                                }
                                HStack {
                                    Image(systemName: "4.circle.fill")
                                        .foregroundColor(.purple)
                                    Text("倒推得到 48 位密钥")
                                        .font(.caption)
                                }
                            }
                            .padding(.vertical, 4)
                        }
                        
                        // Warning
                        HStack {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundColor(.red)
                            Text("此攻击需要约 500 次认证，每次等待卡片响应，预计 2-3 分钟")
                                .font(.caption)
                                .foregroundColor(.red)
                        }
                        .padding(.horizontal)
                    }
                    .padding()
                }
                
                Spacer()
                
                // Results
                if let key = darkSideAttack.foundKey {
                    VStack(spacing: 8) {
                        Text("已恢复密钥:")
                            .font(.subheadline)
                        Text(key.map { String(format: "%02X", $0) }.joined(separator: " "))
                            .font(.system(.title3, design: .monospaced))
                            .foregroundColor(.green)
                            .fontWeight(.bold)
                    }
                    .padding()
                    .background(Color.green.opacity(0.1))
                    .cornerRadius(12)
                    .padding(.horizontal)
                }
                
                Button(action: { startDarkSide() }) {
                    Text("开始暗侧攻击")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.purple)
                        .foregroundColor(.white)
                        .cornerRadius(12)
                }
                .disabled(darkSideAttack.isRunning)
                .padding()
            }
        }
        .navigationTitle("暗侧攻击")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarLeading) {
                if !darkSideAttack.isRunning {
                    Button("取消") { dismiss() }
                }
            }
        }
    }
    
    private func startDarkSide() {
        let block = targetSector < 32
            ? UInt8(targetSector * 4 + 3)
            : UInt8(128 + (targetSector - 32) * 16 + 15)
        
        Task {
            do {
                _ = try await darkSideAttack.recoverKey(
                    targetBlock: block,
                    keyType: useKeyA ? 0x60 : 0x61
                )
            } catch {
                // Handled in DarkSideAttack state
            }
        }
    }
}

// MARK: - Extended KeyManagerView with Attack Views
extension KeyManagerView {
    // The KeyManagerView already includes the dictionary attack as a sheet
    // We extend it with nested and darkside attack options
}