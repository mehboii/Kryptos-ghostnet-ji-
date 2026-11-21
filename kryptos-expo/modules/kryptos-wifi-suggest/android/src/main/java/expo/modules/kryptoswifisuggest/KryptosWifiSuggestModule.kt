package expo.modules.kryptoswifisuggest

import android.content.Context
import android.net.wifi.WifiManager
import android.net.wifi.WifiNetworkSuggestion
import android.os.Build
import expo.modules.kotlin.exception.Exceptions
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

/**
 * Ghost Shield — non-persistent MAC randomization for Kryptos-managed networks.
 *
 * SCOPE (read before touching): this flips the OS MAC-randomization *policy* on the
 * Wi-Fi networks Kryptos itself suggests via {@link WifiNetworkSuggestion}. It is
 * NOT app-driven MAC rotation: we never read, set, or rotate the hardware MAC. We
 * only ask the OS to present a FRESH randomized MAC each time the device rejoins a
 * Kryptos mesh/relay network (RANDOMIZATION_NON_PERSISTENT) instead of reusing one
 * persistent randomized MAC. Everything else stays OS-managed.
 *
 * IMPORTANT — what this canNOT do:
 *   - It applies ONLY to networks Kryptos adds via the suggestion API. It does NOT
 *     and CANNOT affect the user's home/office/cafe Wi-Fi.
 *   - setMacRandomizationSetting(RANDOMIZATION_NON_PERSISTENT) requires Android 12
 *     (API 31). On older devices the suggestion is still registered, but with the
 *     OS default randomization — so we report active=false / the version reason and
 *     never claim non-persistent is in effect.
 *   - We never fabricate or print a MAC value.
 */
class KryptosWifiSuggestModule : Module() {

  private val context: Context
    get() = appContext.reactContext ?: throw Exceptions.ReactContextLost()

  private val wifiManager: WifiManager?
    get() = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager

  override fun definition() = ModuleDefinition {
    Name("KryptosWifiSuggest")

    AsyncFunction("supportsNonPersistentRandomization") {
      Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
    }

    // networks: list of { ssid: String, passphrase?: String } describing Kryptos's
    // OWN mesh/relay networks. Never the user's saved networks.
    AsyncFunction("applyMeshNetworkMacRandomization") { networks: List<Map<String, Any?>> ->
      applyInternal(networks)
    }

    AsyncFunction("clearMeshNetworkSuggestions") {
      clearInternal()
    }
  }

  private fun applyInternal(networks: List<Map<String, Any?>>): Map<String, Any?> {
    val mgr = wifiManager
      ?: return result(requested = true, active = false, reason = "wifi-unavailable")

    val specs = networks.mapNotNull { spec ->
      val ssid = (spec["ssid"] as? String)?.takeIf { it.isNotEmpty() } ?: return@mapNotNull null
      val passphrase = (spec["passphrase"] as? String)?.takeIf { it.isNotEmpty() }
      ssid to passphrase
    }
    if (specs.isEmpty()) {
      return result(requested = true, active = false, reason = "no-mesh-networks")
    }

    // Android 12+ is the hard gate for NON_PERSISTENT randomization on a suggestion.
    val nonPersistentSupported = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S

    return try {
      val suggestions = specs.map { (ssid, passphrase) ->
        val builder = WifiNetworkSuggestion.Builder().setSsid(ssid)
        if (passphrase != null) {
          builder.setWpa2Passphrase(passphrase)
        }
        // GUARD: only flip the randomization policy on API 31+. Below that the
        // method does not exist; the suggestion still registers with the OS default.
        if (nonPersistentSupported) {
          builder.setMacRandomizationSetting(
            WifiNetworkSuggestion.RANDOMIZATION_NON_PERSISTENT
          )
        }
        builder.build()
      }

      // Make re-application idempotent: withdraw our previous suggestions first so
      // a tier toggle does not accumulate duplicates or hit ADD_DUPLICATE.
      mgr.removeNetworkSuggestions(emptyList<WifiNetworkSuggestion>())
      val status = mgr.addNetworkSuggestions(suggestions)
      val added = status == WifiManager.STATUS_NETWORK_SUGGESTIONS_SUCCESS

      when {
        !nonPersistentSupported ->
          // Registered, but the requested non-persistent policy is unavailable here.
          result(requested = true, active = false, reason = "requires-android-12")
        !added ->
          result(requested = true, active = false, reason = "suggestion-rejected-$status")
        else ->
          // The OS now manages a fresh randomized MAC per rejoin for Kryptos's own
          // networks. We do not know (and never log) the MAC value itself.
          result(requested = true, active = true, reason = null)
      }
    } catch (e: SecurityException) {
      result(requested = true, active = false, reason = "permission-denied")
    } catch (e: Exception) {
      result(requested = true, active = false, reason = (e.message ?: "suggestion-failed"))
    }
  }

  private fun clearInternal(): Map<String, Any?> {
    val mgr = wifiManager ?: return result(requested = false, active = false, reason = "wifi-unavailable")
    return try {
      mgr.removeNetworkSuggestions(emptyList<WifiNetworkSuggestion>())
      result(requested = false, active = false, reason = null)
    } catch (e: Exception) {
      result(requested = false, active = false, reason = (e.message ?: "clear-failed"))
    }
  }

  private fun result(requested: Boolean, active: Boolean, reason: String?): Map<String, Any?> =
    mapOf("requested" to requested, "active" to active, "reason" to reason)
}
