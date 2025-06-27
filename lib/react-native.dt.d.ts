declare module 'react-native' {
    namespace NativeModules {
        interface CSRModule {
            generateCSR?(options: {
                commonName: string;
                country?: string;
            }): Promise<string>;
        }
        interface MQTTModule {
            connect?(options: {
                host: string;
                port: number;
                clientId: string;
            }): Promise<boolean>;
        }
        const CSRModule: CSRModule;
        const MQTTModule: MQTTModule;
    }
}
