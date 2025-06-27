export interface CSRModuleType {
    generateCSR?(options: {
        commonName: string;
        country?: string;
    }): Promise<string>;
}
export interface MQTTModuleType {
    connect?(options: {
        host: string;
        port: number;
        clientId: string;
    }): Promise<boolean>;
    disconnect?(): Promise<void>;
    publish?(topic: string, payload: string): Promise<boolean>;
}
declare const _default: {
    CSRModule: CSRModuleType;
    MQTTModule: MQTTModuleType;
};
export default _default;
