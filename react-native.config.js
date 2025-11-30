module.exports = {
  dependency: {
    platforms: {
      android: {
        packageImportPath: 'import com.reactnativemqttmtls.MqttMtlsPackage;',
        packageInstance: 'new MqttMtlsPackage()',
      },
      ios: {
        // iOS support can be added here in the future
        // podspecPath: 'react-native-mqtt-mtls.podspec',
      },
    },
  },
};
