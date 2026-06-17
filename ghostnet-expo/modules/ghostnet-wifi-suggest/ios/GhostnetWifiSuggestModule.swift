import ExpoModulesCore

/**
 * iOS half of ghostnet-wifi-suggest.
 *
 * iOS exposes NO app API to set a per-network MAC-randomization policy: Apple
 * manages this itself via "Private Wi-Fi Address" (a per-SSID randomized MAC,
 * rotating since iOS 18). An app cannot opt a network into non-persistent
 * randomization. Rather than fake it, this module reports UNAVAILABLE with that
 * reason so Ghost Shield surfaces the honest platform truth. We never fabricate a
 * MAC value.
 */
public class GhostnetWifiSuggestModule: Module {
  public func definition() -> ModuleDefinition {
    Name("GhostnetWifiSuggest")

    AsyncFunction("supportsNonPersistentRandomization") { () -> Bool in
      return false
    }

    AsyncFunction("applyMeshNetworkMacRandomization") { (_: [[String: Any]]) -> [String: Any?] in
      return [
        "requested": true,
        "active": false,
        "reason": "ios-os-managed-private-wifi"
      ]
    }

    AsyncFunction("clearMeshNetworkSuggestions") { () -> [String: Any?] in
      return ["requested": false, "active": false, "reason": "ios-os-managed-private-wifi"]
    }
  }
}
