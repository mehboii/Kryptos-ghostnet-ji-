Pod::Spec.new do |s|
  s.name           = 'KryptosWifiSuggest'
  s.version        = '0.1.0'
  s.summary        = 'Non-persistent MAC randomization policy for Kryptos-suggested Wi-Fi networks (Android-only capability)'
  s.description    = 'Android 12+ lets an app set the MAC-randomization policy on the Wi-Fi networks it suggests via WifiNetworkSuggestion. iOS has no such app API (OS-managed Private Wi-Fi Address), so the iOS half reports unavailable instead of faking it.'
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
