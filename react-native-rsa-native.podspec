#
#  Be sure to run `pod spec lint RNRSA.podspec' to ensure this is a
#  valid spec and to remove all comments including this before submitting the spec.
#
#  To learn more about Podspec attributes see http://docs.cocoapods.org/specification.html
#  To see working Podspecs in the CocoaPods repo see https://github.com/CocoaPods/Specs/
#

Pod::Spec.new do |s|
 s.name         = "react-native-rsa-native"
  s.author       = { "Amitay Molko" => "amitaymolko@gmail.com" }

  s.version      = "0.1.0"
  s.summary      = "A native implementation of RSA key generation and encryption/decryption."
  s.license      = "MIT"

  s.homepage     = "https://github.com/amitaymolko/react-native-rsa-native"
  s.source       = { git: "https://github.com/amitaymolko/react-native-rsa-native", :tag => "#{s.version}" }

  s.requires_arc = true
  s.source_files  = "ios/*"
  s.platform     = :ios, "7.0"

  s.dependency "MIHCrypto", "~> 0.4.1"
  s.dependency "React"

end
