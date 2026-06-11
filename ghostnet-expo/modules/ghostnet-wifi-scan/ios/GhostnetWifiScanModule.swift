import ExpoModulesCore

/**
 * iOS half of ghostnet-wifi-scan.
 *
 * iOS provides NO public API to enumerate surrounding WiFi access points
 * (NEHotspotHelper is gated to a special Apple entitlement; CoreWLAN is macOS
 * only). Rather than fake a list, this module always reports `available = false`
 * so Ghost Radar can hide the WiFi section on iOS with an honest note.
 */
public class GhostnetWifiScanModule: Module {
  public func definition() -> ModuleDefinition {
    Name("GhostnetWifiScan")

    AsyncFunction("scan") { () -> [String: Any] in
      return [
        "available": false,
        "reason": "ios-unsupported",
        "accessPoints": [[String: Any]]()
      ]
    }
  }
}
