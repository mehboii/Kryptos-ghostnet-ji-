import ExpoModulesCore
import CoreBluetooth

/**
 * Peripheral (advertise + GATT server) half of Proximity Connect for iOS.
 *
 * CoreBluetooth restrictions we design around:
 *  - Custom manufacturer/service data is NOT advertised, and the local name is
 *    dropped in the background. So we advertise ONLY the rendezvous Service UUID
 *    (CBAdvertisementDataServiceUUIDsKey). The rotating pseudonym is accepted but
 *    not advertised on iOS — rich/identity data is exchanged only after GATT.
 *  - Backgrounded both-roles BLE is heavily throttled; we target foreground.
 */
public class KryptosBlePeripheralModule: Module, CBPeripheralManagerDelegate {

  private var peripheralManager: CBPeripheralManager?
  private var serviceUUID: CBUUID?
  private var peerId: String = ""
  private var publicKeyHex: String = ""

  private var charPeerIdUUID: CBUUID?
  private var charPubKeyUUID: CBUUID?
  private var charDataUUID: CBUUID?

  private var dataCharacteristic: CBMutableCharacteristic?
  private var subscribedCentrals: [CBCentral] = []
  private var wantAdvertising = false

  public func definition() -> ModuleDefinition {
    Name("KryptosBlePeripheral")

    Events(
      "onCentralWrite",
      "onCentralConnected",
      "onCentralDisconnected",
      "onStateChange",
      "onError"
    )

    OnCreate {
      // Allocate lazily on first start so we don't trigger the BT permission
      // prompt before the user opens Proximity Connect.
    }

    AsyncFunction("isPeripheralSupported") { () -> Bool in
      // Any iOS device with BLE can act as a peripheral. The real gate is the
      // user's Bluetooth permission + power state, surfaced via onStateChange.
      return true
    }

    AsyncFunction("configure") { (values: [String: Any]) in
      self.peerId = values["peerId"] as? String ?? ""
      self.publicKeyHex = values["publicKeyHex"] as? String ?? ""
      if let s = values["charPeerIdUuid"] as? String { self.charPeerIdUUID = CBUUID(string: s) }
      if let s = values["charPubKeyUuid"] as? String { self.charPubKeyUUID = CBUUID(string: s) }
      if let s = values["charDataUuid"] as? String { self.charDataUUID = CBUUID(string: s) }
    }

    AsyncFunction("startAdvertising") { (options: [String: Any]) -> Bool in
      if let s = options["serviceUuid"] as? String { self.serviceUUID = CBUUID(string: s) }
      self.wantAdvertising = true
      if self.peripheralManager == nil {
        self.peripheralManager = CBPeripheralManager(delegate: self, queue: nil)
      } else {
        self.bringUpServiceAndAdvertise()
      }
      return true
    }

    AsyncFunction("updatePseudonym") { (_: String) in
      // iOS does not advertise service data, so the pseudonym is a no-op here.
      // The advertisement carries only the rendezvous UUID by design.
    }

    AsyncFunction("notifyData") { (base64: String) in
      guard let data = Data(base64Encoded: base64),
            let ch = self.dataCharacteristic,
            let mgr = self.peripheralManager else { return }
      mgr.updateValue(data, for: ch, onSubscribedCentrals: nil)
    }

    AsyncFunction("stopAdvertising") {
      self.wantAdvertising = false
      self.peripheralManager?.stopAdvertising()
      self.peripheralManager?.removeAllServices()
      self.subscribedCentrals.removeAll()
      self.sendEvent("onStateChange", ["state": "idle"])
    }

    OnDestroy {
      self.peripheralManager?.stopAdvertising()
      self.peripheralManager?.removeAllServices()
    }
  }

  private func bringUpServiceAndAdvertise() {
    guard let mgr = peripheralManager, mgr.state == .poweredOn,
          let svc = serviceUUID, wantAdvertising else { return }

    mgr.removeAllServices()

    var characteristics: [CBMutableCharacteristic] = []

    if let idUUID = charPeerIdUUID {
      characteristics.append(CBMutableCharacteristic(
        type: idUUID, properties: [.read], value: peerId.data(using: .utf8), permissions: [.readable]))
    }
    if let pkUUID = charPubKeyUUID {
      characteristics.append(CBMutableCharacteristic(
        type: pkUUID, properties: [.read], value: dataFromHex(publicKeyHex), permissions: [.readable]))
    }
    if let dataUUID = charDataUUID {
      // value: nil => dynamic value, served via delegate callbacks (required for
      // write + notify characteristics).
      let dataChar = CBMutableCharacteristic(
        type: dataUUID,
        properties: [.write, .writeWithoutResponse, .notify],
        value: nil,
        permissions: [.writeable])
      dataCharacteristic = dataChar
      characteristics.append(dataChar)
    }

    let service = CBMutableService(type: svc, primary: true)
    service.characteristics = characteristics
    mgr.add(service)

    mgr.startAdvertising([CBAdvertisementDataServiceUUIDsKey: [svc]])
    sendEvent("onStateChange", ["state": "advertising"])
  }

  // MARK: - CBPeripheralManagerDelegate

  public func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
    switch peripheral.state {
    case .poweredOn:
      sendEvent("onStateChange", ["state": "poweredOn"])
      bringUpServiceAndAdvertise()
    case .poweredOff:
      sendEvent("onStateChange", ["state": "poweredOff"])
    case .unauthorized:
      sendEvent("onError", ["message": "Bluetooth permission denied", "phase": "permission"])
    case .unsupported:
      sendEvent("onError", ["message": "BLE peripheral unsupported", "phase": "start"])
    default:
      sendEvent("onStateChange", ["state": "resetting"])
    }
  }

  public func peripheralManager(_ peripheral: CBPeripheralManager,
                                didReceiveRead request: CBATTRequest) {
    var value: Data?
    if request.characteristic.uuid == charPeerIdUUID {
      value = peerId.data(using: .utf8)
    } else if request.characteristic.uuid == charPubKeyUUID {
      value = dataFromHex(publicKeyHex)
    }
    guard let full = value else {
      peripheral.respond(to: request, withResult: .attributeNotFound)
      return
    }
    if request.offset > full.count {
      peripheral.respond(to: request, withResult: .invalidOffset)
      return
    }
    request.value = full.subdata(in: request.offset..<full.count)
    peripheral.respond(to: request, withResult: .success)
  }

  public func peripheralManager(_ peripheral: CBPeripheralManager,
                                didReceiveWrite requests: [CBATTRequest]) {
    for request in requests {
      if request.characteristic.uuid == charDataUUID, let data = request.value {
        sendEvent("onCentralWrite", [
          "deviceId": request.central.identifier.uuidString,
          "base64": data.base64EncodedString()
        ])
      }
    }
    if let first = requests.first {
      peripheral.respond(to: first, withResult: .success)
    }
  }

  public func peripheralManager(_ peripheral: CBPeripheralManager,
                                central: CBCentral,
                                didSubscribeTo characteristic: CBCharacteristic) {
    subscribedCentrals.append(central)
    sendEvent("onCentralConnected", ["deviceId": central.identifier.uuidString])
  }

  public func peripheralManager(_ peripheral: CBPeripheralManager,
                                central: CBCentral,
                                didUnsubscribeFrom characteristic: CBCharacteristic) {
    subscribedCentrals.removeAll { $0.identifier == central.identifier }
    sendEvent("onCentralDisconnected", ["deviceId": central.identifier.uuidString])
  }

  // MARK: - Helpers

  private func dataFromHex(_ hex: String) -> Data {
    var clean = hex
    if clean.hasPrefix("0x") { clean = String(clean.dropFirst(2)) }
    guard clean.count % 2 == 0 else { return Data() }
    var data = Data(capacity: clean.count / 2)
    var idx = clean.startIndex
    while idx < clean.endIndex {
      let next = clean.index(idx, offsetBy: 2)
      if let byte = UInt8(clean[idx..<next], radix: 16) {
        data.append(byte)
      } else {
        return Data()
      }
      idx = next
    }
    return data
  }
}
