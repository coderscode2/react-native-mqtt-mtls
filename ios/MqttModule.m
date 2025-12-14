#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(MqttModule, RCTEventEmitter)

RCT_EXTERN_METHOD(connect:(NSString *)broker
                  clientId:(NSString *)clientId
                  certificates:(NSDictionary *)certificates
                  successCallback:(RCTResponseSenderBlock)successCallback
                  errorCallback:(RCTResponseSenderBlock)errorCallback)

RCT_EXTERN_METHOD(subscribe:(NSString *)topic
                  qos:(NSInteger)qos
                  successCallback:(RCTResponseSenderBlock)successCallback
                  errorCallback:(RCTResponseSenderBlock)errorCallback)

RCT_EXTERN_METHOD(unsubscribe:(NSString *)topic
                  successCallback:(RCTResponseSenderBlock)successCallback
                  errorCallback:(RCTResponseSenderBlock)errorCallback)

RCT_EXTERN_METHOD(publish:(NSString *)topic
                  message:(NSString *)message
                  qos:(NSInteger)qos
                  retained:(BOOL)retained
                  successCallback:(RCTResponseSenderBlock)successCallback
                  errorCallback:(RCTResponseSenderBlock)errorCallback)

RCT_EXTERN_METHOD(disconnect:(RCTResponseSenderBlock)successCallback
                  errorCallback:(RCTResponseSenderBlock)errorCallback)

RCT_EXTERN_METHOD(isConnected:(RCTResponseSenderBlock)callback)

@end
