Pod::Spec.new do |s|
  s.name           = 'GhostnetBlePeripheral'
  s.version        = '0.1.0'
  s.summary        = 'BLE peripheral (advertise + GATT server) for GhostNet Proximity Connect'
  s.description    = 'Supplies the advertising + GATT-server role that react-native-ble-plx cannot, so a phone is discoverable while it scans.'
  s.author         = 'GhostNet'
  s.homepage       = 'https://ghostnet.local'
  s.platforms      = { :ios => '15.1', :tvos => '15.1' }
  s.source         = { git: '' }
  s.static_framework = true

  s.dependency 'ExpoModulesCore'

  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'SWIFT_COMPILATION_MODE' => 'wholemodule'
  }

  s.source_files = "**/*.{h,m,mm,swift,hpp,cpp}"
end
