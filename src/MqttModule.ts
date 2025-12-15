import { NativeModules } from 'react-native';
import type { MqttCertificates } from './types';

interface MqttModuleType {
  connect(
    broker: string,
    clientId: string,
    sniHostname?: string,
    brokerIp?: string,
    certificates: MqttCertificates,
    successCallback: (message: string) => void,
    errorCallback: (error: string) => void
  ): void;
  disconnect(
    successCallback: (message: string) => void,
    errorCallback: (error: string) => void
  ): void;
  subscribe(
    topic: string,
    qos: number,
    successCallback: (message: string) => void,
    errorCallback: (error: string) => void
  ): void;
  unsubscribe(
    topic: string,
    successCallback: (message: string) => void,
    errorCallback: (error: string) => void
  ): void;
  publish(
    topic: string,
    message: string,
    qos: number,
    retained: boolean,
    successCallback: (message: string) => void,
    errorCallback: (error: string) => void
  ): void;
  isConnected(callback: (isConnected: boolean) => void): void;
}

const { MqttModule } = NativeModules;

if (!MqttModule) {
  throw new Error(
    'MqttModule native module not found. Make sure you have properly linked the native module and rebuilt your app.'
  );
}

export default MqttModule as MqttModuleType;
