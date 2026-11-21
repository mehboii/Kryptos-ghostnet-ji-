package expo.modules.kryptoswifiscan

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager
import android.os.Build
import androidx.core.content.ContextCompat
import expo.modules.kotlin.exception.Exceptions
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

/**
 * Android nearby WiFi access-point scan for Ghost Radar.
 *
 * Returns the access points the OS currently knows about via WifiManager. This
 * lists ROUTERS / HOTSPOTS — never other phones. Modern Android heavily throttles
 * startScan() (a few scans per couple of minutes), so we kick a refresh but read
 * the last cached results immediately; the radar polls and naturally picks up
 * refreshed lists over time.
 *
 * Required runtime permissions (requested by the JS layer):
 *   - ACCESS_FINE_LOCATION (the OS ties AP scan results to location)
 *   - NEARBY_WIFI_DEVICES on Android 13+ (with neverForLocation it's enough)
 * Without them, getScanResults() returns empty and we report 'permission-denied'.
 */
class KryptosWifiScanModule : Module() {

  private val context: Context
    get() = appContext.reactContext ?: throw Exceptions.ReactContextLost()

  private val wifiManager: WifiManager?
    get() = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager

  override fun definition() = ModuleDefinition {
    Name("KryptosWifiScan")

    AsyncFunction("scan") {
      scanInternal()
    }
  }

  private fun hasScanPermission(): Boolean {
    val fineLocation = ContextCompat.checkSelfPermission(
      context, Manifest.permission.ACCESS_FINE_LOCATION
    ) == PackageManager.PERMISSION_GRANTED
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
      val nearby = ContextCompat.checkSelfPermission(
        context, Manifest.permission.NEARBY_WIFI_DEVICES
      ) == PackageManager.PERMISSION_GRANTED
      // Either path can satisfy the read depending on how the manifest declares it.
      return fineLocation || nearby
    }
    return fineLocation
  }

  @Suppress("DEPRECATION")
  private fun scanInternal(): Map<String, Any?> {
    val mgr = wifiManager
      ?: return result(false, "wifi-unavailable", emptyList())

    if (!mgr.isWifiEnabled) {
      return result(false, "wifi-disabled", emptyList())
    }
    if (!hasScanPermission()) {
      return result(false, "permission-denied", emptyList())
    }

    return try {
      // Best-effort refresh. startScan() is deprecated + throttled on modern
      // Android; ignore its boolean and read whatever cached results exist.
      try { mgr.startScan() } catch (_: Exception) {}

      val results: List<ScanResult> = mgr.scanResults ?: emptyList()
      val aps = results.map { r ->
        mapOf(
          "ssid" to (ssidOf(r)),
          "bssid" to (r.BSSID ?: ""),
          "rssi" to r.level,
          "frequency" to r.frequency,
          "capabilities" to (r.capabilities ?: "")
        )
      }
      result(true, "ok", aps)
    } catch (e: SecurityException) {
      result(false, "permission-denied", emptyList())
    } catch (e: Exception) {
      result(false, (e.message ?: "scan-failed"), emptyList())
    }
  }

  @Suppress("DEPRECATION")
  private fun ssidOf(r: ScanResult): String {
    // A hidden/cloaked network advertises an empty SSID; return "" and let the
    // JS layer decide how to surface it — never invent a name.
    val raw = r.SSID ?: ""
    return raw.removePrefix("\"").removeSuffix("\"")
  }

  private fun result(available: Boolean, reason: String, aps: List<Map<String, Any?>>): Map<String, Any?> =
    mapOf("available" to available, "reason" to reason, "accessPoints" to aps)
}
