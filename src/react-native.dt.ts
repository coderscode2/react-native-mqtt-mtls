declare module 'react-native' {
  export namespace NativeModules {
    export interface CSRModule {
      generateCSR?(options: { commonName: string; country?: string }): Promise<string>;
    }
    export interface MQTTModule {
      connect?(options: { host: string; port: number; clientId: string }): Promise<boolean>;
    }
    export const CSRModule: CSRModule;
    export const MQTTModule: MQTTModule;
  }
}