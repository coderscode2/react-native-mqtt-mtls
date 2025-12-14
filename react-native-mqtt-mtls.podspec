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
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]
  s.platforms    = { :ios => "12.0" }
  s.source       = { :git => package["repository"]["url"], :tag => "#{s.version}" }
  
  s.source_files = "ios/**/*.{h,m,swift}"
  s.requires_arc = true

  # Make this a static framework to work with Swift pods
  s.static_framework = true
  
  # Enable module map generation
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES'
  }

  s.dependency "React-Core"
  s.dependency "CocoaMQTT", "~> 2.1.0"
  
  # Explicitly add the socket dependency with version that supports modular headers
  s.dependency "CocoaAsyncSocket", "~> 7.6"
end
