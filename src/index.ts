import { NativeModules } from 'react-native';

const { CSRModule, MQTTModule } = NativeModules;

export interface CSRModuleType {
  generateCSR?(options: { commonName: string; country?: string }): Promise<string>;
  // Add other methods based on your CSRModule.java
}

export interface MQTTModuleType {
  connect?(options: { host: string; port: number; clientId: string }): Promise<boolean>;
  disconnect?(): Promise<void>;
  publish?(topic: string, payload: string): Promise<boolean>;
  // Add other methods based on your MQTTModule.java
}

export default {
  CSRModule: CSRModule as CSRModuleType,
  MQTTModule: MQTTModule as MQTTModuleType,
};