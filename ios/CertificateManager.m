#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(CertificateManager, NSObject)

RCT_EXTERN_METHOD(storePrivateKey:(NSString *)privateKeyPEM
                  alias:(NSString *)alias
                  callback:(RCTResponseSenderBlock)callback)

RCT_EXTERN_METHOD(storeCertificate:(NSString *)certificatePEM
                  alias:(NSString *)alias
                  callback:(RCTResponseSenderBlock)callback)

RCT_EXTERN_METHOD(deletePrivateKey:(NSString *)alias
                  callback:(RCTResponseSenderBlock)callback)

RCT_EXTERN_METHOD(deleteCertificate:(NSString *)alias
                  callback:(RCTResponseSenderBlock)callback)

RCT_EXTERN_METHOD(listKeychainItems:(RCTResponseSenderBlock)callback)

@end
