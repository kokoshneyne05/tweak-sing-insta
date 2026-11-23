#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, IPSingBoxState) {
    IPSingBoxStateStopped = 0,
    IPSingBoxStateStarting = 1,
    IPSingBoxStateRunning = 2,
    IPSingBoxStateStopping = 3,
    IPSingBoxStateError = 4
};

extern NSString *const kInstaProxyStatusDidChangeNotification;

@interface SingBoxController : NSObject

+ (instancetype)sharedController;

@property (nonatomic, assign, readonly) IPSingBoxState state;
@property (nonatomic, copy, readonly, nullable) NSString *lastErrorMessage;
@property (nonatomic, copy, readonly, nullable) NSString *activeServerName;
@property (nonatomic, assign, readonly) NSInteger activeServerDelayMs;
@property (nonatomic, copy, readonly) NSString *coreVersion;

/// Automatically starts sing-box on app launch when enabled in UserDefaults and nodes exist.
- (void)startIfEnabled;

/// Starts sing-box core, updates bypass IPs, waits for 127.0.0.1:10808, and enables ProxyInterceptor.
- (void)startWithCompletion:(nullable void (^)(BOOL success, NSError * _Nullable error))completion;

/// Disables ProxyInterceptor immediately and cleanly stops the running sing-box core.
- (void)stopWithCompletion:(nullable void (^)(void))completion;

/// Stops (if running) and restarts sing-box with freshly generated configuration and resolved bypass IPs.
- (void)restartWithCompletion:(nullable void (^)(BOOL success, NSError * _Nullable error))completion;

/// Selects "auto" (urltest) or a specific node tag. Persists to UserDefaults and applies live if running.
- (void)selectOutboundTag:(NSString *)tag
               completion:(nullable void (^)(BOOL appliedLive, NSError * _Nullable error))completion;

/// Queries the local sing-box Clash API (127.0.0.1:19090/proxies) for the currently active server and latency.
- (void)refreshActiveServerWithCompletion:(nullable void (^)(NSString * _Nullable activeServer, NSInteger delayMs))completion;

@end

NS_ASSUME_NONNULL_END
