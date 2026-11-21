Pod::Spec.new do |s|
  s.name           = 'KryptosWifiScan'
  s.version        = '0.1.0'
  s.summary        = 'Nearby WiFi access-point scan for Kryptos Ghost Radar (Android-only capability)'
  s.description    = 'Android exposes nearby WiFi access points via WifiManager. iOS has no public API for this, so the iOS half reports unavailable instead of faking results.'
  s.author         = 'Kryptos'
  s.homepage       = 'https://kryptos.local'
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
