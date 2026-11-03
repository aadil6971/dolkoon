import SwiftUI
import AppKit

@main
struct DolkoonApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup("Dolkoon", id: "main") {
            RootView().environmentObject(model)
                .frame(minWidth: 900, minHeight: 600)
                .preferredColorScheme(.dark)
        }
        .windowToolbarStyle(.unified(showsTitle: false))
        MenuBarExtra {
            MenuView().environmentObject(model)
        } label: {
            MenuLabel().environmentObject(model)
        }
        .menuBarExtraStyle(.window)
    }
}
