import SwiftUI

// MARK: - Main Tab View
struct ContentView: View {
    @StateObject private var bleManager: BLEManager
    @StateObject private var keyStore = KeyStore()
    @StateObject private var mifareController: MIFAREController
    @StateObject private var nestedAttack: NestedAttack
    @StateObject private var darkSideAttack: DarkSideAttack
    @StateObject private var dictionaryAttack: DictionaryAttack
    @StateObject private var magicController: MagicCardController
    
    @State private var selectedTab = 0
    @State private var showScanner = false
    @State private var selectedDevice: BLEDevice?
    @State private var selectedSector: MIFARESector?
    
    init() {
        let ble = BLEManager()
        _bleManager = StateObject(wrappedValue: ble)
        
        let mifare = MIFAREController(bleManager: ble)
        _mifareController = StateObject(wrappedValue: mifare)
        
        _nestedAttack = StateObject(wrappedValue: NestedAttack(bleManager: ble, mifareController: mifare))
        _darkSideAttack = StateObject(wrappedValue: DarkSideAttack(bleManager: ble))
        _dictionaryAttack = StateObject(wrappedValue: DictionaryAttack(bleManager: ble))
        _magicController = StateObject(wrappedValue: MagicCardController(bleManager: ble))
    }
    
    var body: some View {
        TabView(selection: $selectedTab) {
            // Tab 1: Device & Card (with Nested Attack & Magic Card Tools)
            NavigationView {
                mainDeviceView
                    .navigationTitle("PCR532 Pro")
                    .toolbar {
                        ToolbarItem(placement: .navigationBarLeading) {
                            if bleManager.isConnected {
                                Button(action: { bleManager.disconnect() }) {
                                    Image(systemName: "power")
                                        .foregroundColor(.red)
                                }
                            }
                        }
                        ToolbarItem(placement: .navigationBarTrailing) {
                            Button(action: { showScanner = true }) {
                                HStack(spacing: 4) {
                                    Circle()
                                        .fill(bleManager.isConnected ? Color.green : Color.red)
                                        .frame(width: 8, height: 8)
                                    Image(systemName: "antenna.radiowaves.left.and.right")
                                }
                            }
                        }
                    }
            }
            .tabItem {
                Label("读卡", systemImage: "creditcard.and.123")
            }
            .tag(0)
            
            // Tab 2: Sectors
            NavigationView {
                SectorListView(
                    mifareController: mifareController,
                    selectedSector: $selectedSector
                )
                .navigationTitle("扇区数据")
                .toolbar {
                    ToolbarItem(placement: .navigationBarTrailing) {
                        if bleManager.isConnected {
                            Button(action: {
                                Task { _ = try? await mifareController.detectCard() }
                            }) {
                                Image(systemName: "waveform.path.ecg")
                            }
                        }
                    }
                }
                .sheet(item: $selectedSector) { sector in
                    SectorDetailView(
                        sector: sector,
                        mifareController: mifareController
                    )
                }
            }
            .tabItem {
                Label("扇区", systemImage: "square.grid.3x3.fill")
            }
            .tag(1)
            
            // Tab 3: Data Management (Dumps & Keys)
            DataManagementView(
                mifareController: mifareController,
                keyStore: keyStore,
                bleManager: bleManager
            )
            .tabItem {
                Label("数据", systemImage: "folder.fill")
            }
            .tag(2)
            
            // Tab 4: Settings
            SettingsView(
                bleManager: bleManager,
                mifareController: mifareController
            )
            .tabItem {
                Label("设置", systemImage: "gearshape.fill")
            }
            .tag(3)
        }
        .accentColor(.blue)
        .fullScreenCover(isPresented: $showScanner) {
            DeviceScanWrapper(
                bleManager: bleManager,
                selectedDevice: $selectedDevice,
                showScanner: $showScanner
            )
        }
        .onAppear {
            // Load saved dumps
            mifareController.loadDumpsFromDisk()
        }
    }
    
    // MARK: - Main Device View
    private var mainDeviceView: some View {
        VStack(spacing: 0) {
            // Connection badge
            HStack {
                ConnectionBadge(
                    isConnected: bleManager.isConnected,
                    deviceName: bleManager.connectedDeviceName
                )
                Spacer()
            }
            .padding(.horizontal)
            .padding(.top, 4)
            
            // Card info section
            CardInfoView(
                cardInfo: mifareController.currentCard,
                mifareController: mifareController,
                bleManager: bleManager,
                nestedAttack: nestedAttack,
                magicController: magicController
            )
        }
    }
}

