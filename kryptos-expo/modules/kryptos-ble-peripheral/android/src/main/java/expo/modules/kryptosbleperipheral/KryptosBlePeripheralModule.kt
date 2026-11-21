package expo.modules.kryptosbleperipheral

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import android.os.Build
import android.os.ParcelUuid
import android.util.Base64
import expo.modules.kotlin.exception.Exceptions
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Peripheral (advertise + GATT server) half of Proximity Connect.
 *
 * Runs concurrently with the central role (react-native-ble-plx) so the phone is
 * discoverable while it scans. Advertises only the shared rendezvous Service UUID
 * plus a rotating pseudonym in service data — never a stable identifier.
 *
 * Runtime permissions (BLUETOOTH_ADVERTISE, BLUETOOTH_CONNECT on API 31+) are the
 * JS layer's responsibility; calls here fail soft and emit `onError` if denied.
 */
class KryptosBlePeripheralModule : Module() {

  private val context: Context
    get() = appContext.reactContext ?: throw Exceptions.ReactContextLost()

  private val bluetoothManager: BluetoothManager?
    get() = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager

  private var advertiser: BluetoothLeAdvertiser? = null
  private var gattServer: BluetoothGattServer? = null
  private var advertiseCallback: AdvertiseCallback? = null

  private var serviceUuid: UUID? = null
  private var pseudonym: ByteArray = ByteArray(0)

  private var peerId: String = ""
  private var publicKeyHex: String = ""
  private var charPeerIdUuid: UUID? = null
  private var charPubKeyUuid: UUID? = null
  private var charDataUuid: UUID? = null
  private var dataCharacteristic: BluetoothGattCharacteristic? = null

  // ParcelUuid for the 16-bit-ish service data slot carrying the pseudonym.
  private val pseudonymServiceDataUuid = ParcelUuid(UUID.fromString("00006768-0000-1000-8000-00805f9b34fb"))

  private val connectedCentrals = ConcurrentHashMap<String, BluetoothDevice>()

  // Standard Client Characteristic Configuration descriptor for notify-enable.
  private val cccdUuid = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

  override fun definition() = ModuleDefinition {
    Name("KryptosBlePeripheral")

    Events(
      "onCentralWrite",
      "onCentralConnected",
      "onCentralDisconnected",
      "onStateChange",
      "onError"
    )

    AsyncFunction("isPeripheralSupported") {
      val adapter = bluetoothManager?.adapter ?: return@AsyncFunction false
      if (!adapter.isEnabled) return@AsyncFunction false
      // The single most important gate: not every Android radio can advertise.
      adapter.isMultipleAdvertisementSupported && adapter.bluetoothLeAdvertiser != null
    }

    AsyncFunction("configure") { values: Map<String, Any?> ->
      peerId = values["peerId"] as? String ?: ""
      publicKeyHex = values["publicKeyHex"] as? String ?: ""
      charPeerIdUuid = (values["charPeerIdUuid"] as? String)?.let { UUID.fromString(it) }
      charPubKeyUuid = (values["charPubKeyUuid"] as? String)?.let { UUID.fromString(it) }
      charDataUuid = (values["charDataUuid"] as? String)?.let { UUID.fromString(it) }
    }

    AsyncFunction("startAdvertising") { options: Map<String, Any?> ->
      serviceUuid = (options["serviceUuid"] as? String)?.let { UUID.fromString(it) }
      pseudonym = hexToBytes(options["pseudonymHex"] as? String ?: "")
      startPeripheral()
    }

    AsyncFunction("updatePseudonym") { hex: String ->
      pseudonym = hexToBytes(hex)
      // Re-issue the advert with the fresh pseudonym; GATT server stays up.
      restartAdvertisingOnly()
    }

    AsyncFunction("notifyData") { base64: String ->
      notifyCentrals(Base64.decode(base64, Base64.NO_WRAP))
    }

    AsyncFunction("stopAdvertising") {
      stopPeripheral()
    }

    OnDestroy {
      stopPeripheral()
    }
  }

  @SuppressLint("MissingPermission")
  private fun startPeripheral(): Boolean {
    val adapter = bluetoothManager?.adapter
    if (adapter == null || !adapter.isEnabled) {
      sendError("Bluetooth adapter unavailable or off", "start")
      return false
    }
    if (!adapter.isMultipleAdvertisementSupported) {
      sendError("This device cannot advertise (isMultipleAdvertisementSupported=false)", "start")
      return false
    }
    val svc = serviceUuid ?: run { sendError("serviceUuid not set", "start"); return false }

    try {
      openGattServer(adapter)
      startAdvertisingInternal(adapter, svc)
      sendEvent("onStateChange", mapOf("state" to "advertising"))
      return true
    } catch (e: SecurityException) {
      sendError("Missing BLUETOOTH_ADVERTISE/CONNECT permission: ${e.message}", "start")
      return false
    } catch (e: Exception) {
      sendError("startPeripheral failed: ${e.message}", "start")
      return false
    }
  }

  @SuppressLint("MissingPermission")
  private fun openGattServer(adapter: android.bluetooth.BluetoothAdapter) {
    val mgr = bluetoothManager ?: return
    gattServer = mgr.openGattServer(context, gattServerCallback)

    val service = BluetoothGattService(serviceUuid, BluetoothGattService.SERVICE_TYPE_PRIMARY)

    charPeerIdUuid?.let {
      service.addCharacteristic(
        BluetoothGattCharacteristic(
          it,
          BluetoothGattCharacteristic.PROPERTY_READ,
          BluetoothGattCharacteristic.PERMISSION_READ
        )
      )
    }
    charPubKeyUuid?.let {
      service.addCharacteristic(
        BluetoothGattCharacteristic(
          it,
          BluetoothGattCharacteristic.PROPERTY_READ,
          BluetoothGattCharacteristic.PERMISSION_READ
        )
      )
    }
    charDataUuid?.let {
      val data = BluetoothGattCharacteristic(
        it,
        BluetoothGattCharacteristic.PROPERTY_WRITE or
          BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE or
          BluetoothGattCharacteristic.PROPERTY_NOTIFY,
        BluetoothGattCharacteristic.PERMISSION_WRITE
      )
      data.addDescriptor(
        BluetoothGattDescriptor(
          cccdUuid,
          BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE
        )
      )
      dataCharacteristic = data
      service.addCharacteristic(data)
    }

    gattServer?.addService(service)
  }

  @SuppressLint("MissingPermission")
  private fun startAdvertisingInternal(adapter: android.bluetooth.BluetoothAdapter, svc: UUID) {
    advertiser = adapter.bluetoothLeAdvertiser
    if (advertiser == null) {
      sendError("bluetoothLeAdvertiser is null", "advertise")
      return
    }

    val settings = AdvertiseSettings.Builder()
      .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
      .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
      .setConnectable(true)
      .setTimeout(0)
      .build()

    val dataBuilder = AdvertiseData.Builder()
      .setIncludeDeviceName(false) // never leak the device name
      .addServiceUuid(ParcelUuid(svc))
    if (pseudonym.isNotEmpty()) {
      dataBuilder.addServiceData(pseudonymServiceDataUuid, pseudonym)
    }

    advertiseCallback = object : AdvertiseCallback() {
      override fun onStartFailure(errorCode: Int) {
        sendError("Advertise failed: code $errorCode", "advertise")
      }
      override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
        sendEvent("onStateChange", mapOf("state" to "advertise_started"))
      }
    }

    advertiser?.startAdvertising(settings, dataBuilder.build(), advertiseCallback)
  }

  @SuppressLint("MissingPermission")
  private fun restartAdvertisingOnly() {
    val adapter = bluetoothManager?.adapter ?: return
    val svc = serviceUuid ?: return
    try {
      advertiseCallback?.let { advertiser?.stopAdvertising(it) }
      startAdvertisingInternal(adapter, svc)
    } catch (e: Exception) {
      sendError("updatePseudonym failed: ${e.message}", "advertise")
    }
  }

  @SuppressLint("MissingPermission")
  private fun notifyCentrals(value: ByteArray) {
    val server = gattServer ?: return
    val ch = dataCharacteristic ?: return
    for (device in connectedCentrals.values) {
      try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
          server.notifyCharacteristicChanged(device, ch, false, value)
        } else {
          @Suppress("DEPRECATION")
          ch.value = value
          @Suppress("DEPRECATION")
          server.notifyCharacteristicChanged(device, ch, false)
        }
      } catch (e: Exception) {
        sendError("notify failed: ${e.message}", "notify")
      }
    }
  }

  @SuppressLint("MissingPermission")
  private fun stopPeripheral() {
    try {
      advertiseCallback?.let { advertiser?.stopAdvertising(it) }
    } catch (_: Exception) {}
    advertiseCallback = null
    advertiser = null
    try {
      gattServer?.close()
    } catch (_: Exception) {}
    gattServer = null
    dataCharacteristic = null
    connectedCentrals.clear()
    sendEvent("onStateChange", mapOf("state" to "idle"))
  }

  private val gattServerCallback = object : BluetoothGattServerCallback() {
    @SuppressLint("MissingPermission")
    override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
      if (newState == BluetoothProfile.STATE_CONNECTED) {
        connectedCentrals[device.address] = device
        sendEvent("onCentralConnected", mapOf("deviceId" to device.address))
      } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
        connectedCentrals.remove(device.address)
        sendEvent("onCentralDisconnected", mapOf("deviceId" to device.address))
      }
    }

    @SuppressLint("MissingPermission")
    override fun onCharacteristicReadRequest(
      device: BluetoothDevice,
      requestId: Int,
      offset: Int,
      characteristic: BluetoothGattCharacteristic
    ) {
      val full: ByteArray = when (characteristic.uuid) {
        charPeerIdUuid -> peerId.toByteArray(Charsets.UTF_8)
        charPubKeyUuid -> hexToBytes(publicKeyHex)
        else -> ByteArray(0)
      }
      val slice = if (offset >= full.size) ByteArray(0) else full.copyOfRange(offset, full.size)
      gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, slice)
    }

    @SuppressLint("MissingPermission")
    override fun onCharacteristicWriteRequest(
      device: BluetoothDevice,
      requestId: Int,
      characteristic: BluetoothGattCharacteristic,
      preparedWrite: Boolean,
      responseNeeded: Boolean,
      offset: Int,
      value: ByteArray
    ) {
      if (characteristic.uuid == charDataUuid) {
        sendEvent(
          "onCentralWrite",
          mapOf(
            "deviceId" to device.address,
            "base64" to Base64.encodeToString(value, Base64.NO_WRAP)
          )
        )
      }
      if (responseNeeded) {
        gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value)
      }
    }

    @SuppressLint("MissingPermission")
    override fun onDescriptorWriteRequest(
      device: BluetoothDevice,
      requestId: Int,
      descriptor: BluetoothGattDescriptor,
      preparedWrite: Boolean,
      responseNeeded: Boolean,
      offset: Int,
      value: ByteArray
    ) {
      // Central enabling/disabling notifications on the CCC descriptor.
      if (responseNeeded) {
        gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value)
      }
    }
  }

  private fun sendError(message: String, phase: String) {
    sendEvent("onError", mapOf("message" to message, "phase" to phase))
  }

  private fun hexToBytes(hex: String): ByteArray {
    val clean = if (hex.startsWith("0x")) hex.substring(2) else hex
    if (clean.isEmpty() || clean.length % 2 != 0) return ByteArray(0)
    return try {
      ByteArray(clean.length / 2) {
        ((Character.digit(clean[it * 2], 16) shl 4) + Character.digit(clean[it * 2 + 1], 16)).toByte()
      }
    } catch (_: Exception) {
      ByteArray(0)
    }
  }
}
