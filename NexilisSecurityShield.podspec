Pod::Spec.new do |spec|
  spec.name         = "NexilisSecurityShield"
  spec.version      = "6.0.8"
  spec.summary      = "Nexilis SecurityShield policy checks"
  spec.description  = <<-DESC
  The server-configured SecurityShield policy for iOS: emulator, jailbreak, outdated OS, cloned
  app, hook/Frida, debugger, screen capture/casting, SIM swap, geovelocity and behavioural
  analysis, each with a "continue" or "exit" action set by the institution. Runs after NexilisZTA
  has authorized the device and before NexilisLite opens its messaging session.
                   DESC

  spec.homepage     = "https://nexilis.io/"
  spec.license      = "MIT"
  spec.author       = { "Nexilis" => "ya2n.wicaksono@gmail.com" }
  spec.ios.deployment_target = "15.0"
  spec.source       = { :git => "https://github.com/alqindiirsyam-es/NexilisSecurityShield.git",
                        :tag => spec.version.to_s }
  spec.source_files = 'NexilisSecurityShield/Source/**/*.swift'
  spec.swift_version = '5.5.1'
  spec.frameworks   = 'Foundation', 'UIKit', 'CoreTelephony', 'CoreLocation', 'CoreMotion',
                      'Network', 'SystemConfiguration', 'CryptoKit', 'Security'

  spec.dependency 'NexilisZTA', '~> 6.0.8'

  # HTTPS only, no nuSDKService: nothing here is device-only, so the Simulator is not excluded.
  spec.pod_target_xcconfig = { 'ENABLE_BITCODE' => 'NO' }
end
