// OPTION 2: Better Structure (Separate Certificates from Connection Config)
// This is more semantically correct but requires more changes

export interface MqttMessage {
  topic: string;
  message: string;
  qos: number;
}

// Pure certificate data
export interface MqttCertificates {
  clientCert: string;
  privateKeyAlias: string;
  rootCa: string;
}

// Connection configuration (includes certificates + SNI)
export interface MqttConnectionConfig {
  certificates: MqttCertificates;
  sniHostname?: string;  // Optional SNI hostname for .local domains
  brokerIp?: string;     // Optional broker IP for bypassing DNS
}

export interface MqttConfig {
  broker: string;
  clientId: string;
  connection: MqttConnectionConfig;  // Changed from 'certificates' to 'connection'
  onMessage?: (message: MqttMessage) => void;
  onConnect?: () => void;
  onConnectionLost?: (error: string) => void;
  onReconnect?: () => void;
  onError?: (error: string) => void;
}

export interface MqttContextType {
  isConnected: boolean;
  error: string | null;
  connect: (config: MqttConfig) => Promise<void>;
  disconnect: () => Promise<void>;
  subscribe: (topic: string, qos?: number) => Promise<void>;
  unsubscribe: (topic: string) => Promise<void>;
  publish: (topic: string, message: string, qos?: number, retained?: boolean) => Promise<void>;
}
