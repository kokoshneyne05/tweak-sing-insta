#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString *const kInstaProxyAutoOutboundTag;
extern NSString *const kInstaProxySelectorOutboundTag;
extern NSString *const kInstaProxySubscriptionsDidChangeNotification;

@interface IPProxySubscription : NSObject
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *name;
@property (nonatomic, copy) NSString *url;
@property (nonatomic, strong, nullable) NSDate *lastUpdated;
@property (nonatomic, assign) NSInteger nodeCount;
@property (nonatomic, copy, nullable) NSString *lastError;

- (NSDictionary<NSString *, id> *)toDictionary;
+ (nullable instancetype)fromDictionary:(NSDictionary<NSString *, id> *)dict;
@end

@interface IPProxyNode : NSObject
@property (nonatomic, copy) NSString *tag;
@property (nonatomic, copy) NSString *displayName;
@property (nonatomic, copy) NSString *protocol;
@property (nonatomic, copy) NSString *server;
@property (nonatomic, assign) NSInteger port;
@property (nonatomic, copy) NSString *subscriptionID;
@property (nonatomic, copy) NSDictionary<NSString *, id> *outboundConfig;

- (NSDictionary<NSString *, id> *)toDictionary;
+ (nullable instancetype)fromDictionary:(NSDictionary<NSString *, id> *)dict;
@end

@interface SubscriptionManager : NSObject

+ (instancetype)sharedManager;

@property (nonatomic, assign) BOOL proxyEnabled;
@property (nonatomic, copy) NSString *selectedTag;
@property (nonatomic, assign, readonly) uint16_t localProxyPort;
@property (nonatomic, assign, readonly) uint16_t clashAPIPort;

@property (nonatomic, copy, readonly) NSArray<IPProxySubscription *> *subscriptions;
@property (nonatomic, copy, readonly) NSArray<IPProxyNode *> *nodes;

/// Adds a new subscription URL, immediately fetches and parses its nodes, and persists to UserDefaults.
- (void)addSubscriptionWithURL:(NSString *)urlString
                          name:(nullable NSString *)name
                    completion:(void (^)(IPProxySubscription * _Nullable subscription, NSError * _Nullable error))completion;

/// Removes a subscription and all nodes belonging to it.
- (void)removeSubscriptionWithIdentifier:(NSString *)identifier;

/// Re-downloads and parses a single subscription by identifier.
- (void)updateSubscriptionWithIdentifier:(NSString *)identifier
                              completion:(void (^)(BOOL success, NSError * _Nullable error))completion;

/// Updates all saved subscriptions concurrently.
- (void)updateAllSubscriptionsWithCompletion:(void (^)(NSInteger updatedCount, NSInteger failedCount, NSError * _Nullable lastError))completion;

/// Generates complete sing-box JSON configuration string with mixed inbound (127.0.0.1:10808),
/// urltest auto-selector, manual selector, and all parsed server outbounds.
- (nullable NSString *)generateSingBoxConfigJSONWithError:(NSError * _Nullable * _Nullable)error;

/// Resolves all server hostnames from currently stored nodes to IPv4/IPv6 strings for loop-free bypass.
- (void)resolveAllNodeServerIPsWithCompletion:(void (^)(NSSet<NSString *> *ipAddresses))completion;

/// Synchronously resolves a single hostname or IP literal to IPv4/IPv6 string addresses.
+ (NSSet<NSString *> *)resolveHostToIPAddresses:(NSString *)host;

/// Parses raw subscription payload (direct sing-box JSON, Base64 URI list, or plain URI list) into nodes.
- (NSArray<IPProxyNode *> *)parseSubscriptionData:(NSData *)data
                                   subscriptionID:(NSString *)subscriptionID
                                            error:(NSError * _Nullable * _Nullable)error;

@end

NS_ASSUME_NONNULL_END
