require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "react-native-mqtt-mtls"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.description  = <<-DESC
                  MQTT with mutual TLS (mTLS) support for React Native.
                  Supports certificate-based authentication for secure IoT connections.
                   DESC
  s.homepage     = "https://github.com/coderscode2/react-native-mqtt-mtls"
  s.license      = package["license"]
  s.authors      = package["author"]
  s.platforms    = { :ios => "12.0" }
  s.source       = { :git => "https://github.com/coderscode2/react-native-mqtt-mtls.git", :tag => "#{s.version}" }

  s.source_files = "ios/**/*.{h,m,swift}"
  s.requires_arc = true

  # Use modular headers
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES'
  }

  s.dependency "React-Core"
  
  # Specify modular headers for CocoaMQTT and its dependencies
  s.dependency "CocoaMQTT", "~> 2.1.0"
  s.dependency "CocoaAsyncSocket", "~> 7.6"
  
  s.static_framework = true
end
