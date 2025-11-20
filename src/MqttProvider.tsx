import React, { createContext, useState, useCallback, useRef, useContext } from 'react';
import { NativeModules, NativeEventEmitter, EmitterSubscription } from 'react-native';
import type { MqttConfig, MqttContextType, MqttMessage } from './types';

const { MqttModule } = NativeModules;

if (!MqttModule) {
  throw new Error(
    'MqttModule is not available. Make sure the native module is properly linked.'
  );
}

const eventEmitter = new NativeEventEmitter(MqttModule);

export const MqttContext = createContext<MqttContextType | undefined>(undefined);

export interface MqttProviderProps {
  children: React.ReactNode;
}

export const MqttProvider: React.FC<MqttProviderProps> = ({ children }) => {
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Store callbacks and subscriptions
  const callbacksRef = useRef<MqttConfig>({} as MqttConfig);
  const subscriptionsRef = useRef<EmitterSubscription[]>([]);

  // Cleanup event listeners
  const cleanupEventListeners = useCallback(() => {
    subscriptionsRef.current.forEach((sub) => sub.remove());
    subscriptionsRef.current = [];
  }, []);

  // Setup event listeners
  const setupEventListeners = useCallback(() => {
    // Clean up any existing listeners first
    cleanupEventListeners();

    // Subscribe to native events
    const messageSubscription = eventEmitter.addListener(
      'MqttMessage',
      (payload: string) => {
        try {
          const message: MqttMessage = JSON.parse(payload);
          callbacksRef.current.onMessage?.(message);
        } catch (err) {
          console.error('Failed to parse MQTT message:', err);
        }
      }
    );

    const connectSubscription = eventEmitter.addListener('MqttConnect', () => {
      setIsConnected(true);
      setError(null);
      callbacksRef.current.onConnect?.();
    });

    const connectionLostSubscription = eventEmitter.addListener(
      'MqttConnectionLost',
      (err: string) => {
        setIsConnected(false);
        setError(err);
        callbacksRef.current.onConnectionLost?.(err);
      }
    );

    const reconnectSubscription = eventEmitter.addListener('MqttReconnect', () => {
      setIsConnected(true);
      setError(null);
      callbacksRef.current.onReconnect?.();
    });

    const errorSubscription = eventEmitter.addListener('MqttError', (err: string) => {
      setError(err);
      callbacksRef.current.onError?.(err);
    });

    subscriptionsRef.current = [
      messageSubscription,
      connectSubscription,
      connectionLostSubscription,
      reconnectSubscription,
      errorSubscription,
    ];
  }, [cleanupEventListeners]);

  const connect = useCallback(
    async (config: MqttConfig) => {
      try {
        // Store callbacks for later use
        callbacksRef.current = config;

        // Setup event listeners
        setupEventListeners();

        // Call native connect method
        await new Promise<void>((resolve, reject) => {
          MqttModule.connect(
            config.broker,
            config.clientId,
            config.certificates,
            () => resolve(),
            (err: string) => reject(new Error(err))
          );
        });

        setIsConnected(true);
        setError(null);
      } catch (err: any) {
        const message = err?.message || 'Unknown error';
        setError(message);
        cleanupEventListeners();
        throw err;
      }
    },
    [setupEventListeners, cleanupEventListeners]
  );

  const disconnect = useCallback(async () => {
    try {
      await new Promise<void>((resolve, reject) => {
        MqttModule.disconnect(
          () => {
            setIsConnected(false);
            setError(null);
            cleanupEventListeners();
            resolve();
          },
          (err: string) => reject(new Error(err))
        );
      });
    } catch (err: any) {
      const message = err?.message || 'Unknown error';
      setError(message);
      throw err;
    }
  }, [cleanupEventListeners]);

  const subscribe = useCallback(
    async (topic: string, qos: number = 1) => {
      if (!isConnected) {
        throw new Error('Not connected to MQTT broker');
      }

      await new Promise<void>((resolve, reject) => {
        MqttModule.subscribe(
          topic,
          qos,
          () => resolve(),
          (err: string) => reject(new Error(err))
        );
      });
    },
    [isConnected]
  );

  const unsubscribe = useCallback(
    async (topic: string) => {
      if (!isConnected) {
        throw new Error('Not connected to MQTT broker');
      }

      await new Promise<void>((resolve, reject) => {
        MqttModule.unsubscribe(
          topic,
          () => resolve(),
          (err: string) => reject(new Error(err))
        );
      });
    },
    [isConnected]
  );

  const publish = useCallback(
    async (topic: string, message: string, qos: number = 1, retained: boolean = false) => {
      if (!isConnected) {
        throw new Error('Not connected to MQTT broker');
      }

      await new Promise<void>((resolve, reject) => {
        MqttModule.publish(
          topic,
          message,
          qos,
          retained,
          () => resolve(),
          (err: string) => reject(new Error(err))
        );
      });
    },
    [isConnected]
  );

  const value: MqttContextType = {
    isConnected,
    error,
    connect,
    disconnect,
    subscribe,
    unsubscribe,
    publish,
  };

  return <MqttContext.Provider value={value}>{children}</MqttContext.Provider>;
};

export const useMqtt = (): MqttContextType => {
  const context = useContext(MqttContext);
  if (context === undefined) {
    throw new Error('useMqtt must be used within an MqttProvider');
  }
  return context;
};
