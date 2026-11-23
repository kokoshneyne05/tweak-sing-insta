#import "SubscriptionManager.h"
#import "ProxyInterceptor.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

NSString *const kInstaProxyAutoOutboundTag = @"auto";
NSString *const kInstaProxySelectorOutboundTag = @"proxy";
NSString *const kInstaProxySubscriptionsDidChangeNotification = @"InstaProxySubscriptionsDidChangeNotification";

static NSString *const kUDKeyProxyEnabled = @"com.instaproxy.enabled";
static NSString *const kUDKeySelectedTag = @"com.instaproxy.selected_tag";
static NSString *const kUDKeySubscriptions = @"com.instaproxy.subscriptions_v1";
static NSString *const kUDKeyNodes = @"com.instaproxy.nodes_v1";
static NSString *const kInstaProxyErrorDomain = @"com.instaproxy.subscription";

// MARK: - Helper Functions

static NSString *IPPercentDecode(NSString *value) {
    if (!value) return @"";
    NSString *decoded = [value stringByRemovingPercentEncoding];
    return decoded ?: value;
}

static NSData * _Nullable IPDecodeFlexibleBase64(NSString *rawString) {
    if (!rawString || rawString.length == 0) return nil;
    NSMutableString *clean = [rawString mutableCopy];
    [clean replaceOccurrencesOfString:@"\r" withString:@"" options:0 range:NSMakeRange(0, clean.length)];
    [clean replaceOccurrencesOfString:@"\n" withString:@"" options:0 range:NSMakeRange(0, clean.length)];
    [clean replaceOccurrencesOfString:@" " withString:@"" options:0 range:NSMakeRange(0, clean.length)];
    [clean replaceOccurrencesOfString:@"\t" withString:@"" options:0 range:NSMakeRange(0, clean.length)];
    [clean replaceOccurrencesOfString:@"-" withString:@"+" options:0 range:NSMakeRange(0, clean.length)];
    [clean replaceOccurrencesOfString:@"_" withString:@"/" options:0 range:NSMakeRange(0, clean.length)];

    NSUInteger rem = clean.length % 4;
    if (rem == 2) {
        [clean appendString:@"=="];
    } else if (rem == 3) {
        [clean appendString:@"="];
    } else if (rem == 1) {
        return nil;
    }

    return [[NSData alloc] initWithBase64EncodedString:clean options:NSDataBase64DecodingIgnoreUnknownCharacters];
}

static NSDictionary<NSString *, NSString *> *IPParseQueryParameters(NSString *query) {
    NSMutableDictionary<NSString *, NSString *> *params = [NSMutableDictionary dictionary];
    if (!query || query.length == 0) return params;
    NSArray<NSString *> *pairs = [query componentsSeparatedByString:@"&"];
    for (NSString *pair in pairs) {
        if (pair.length == 0) continue;
        NSRange eq = [pair rangeOfString:@"="];
        if (eq.location == NSNotFound) {
            NSString *k = IPPercentDecode(pair);
            if (k.length > 0) params[k] = @"";
        } else {
            NSString *k = IPPercentDecode([pair substringToIndex:eq.location]);
            NSString *v = IPPercentDecode([pair substringFromIndex:eq.location + 1]);
            if (k.length > 0) params[k] = v ?: @"";
        }
    }
    return params;
}

static BOOL IPParseHostAndPort(NSString *hostPort, NSString * _Nullable *outHost, NSInteger *outPort) {
    if (!hostPort || hostPort.length == 0) return NO;
    NSString *host = nil;
    NSString *portStr = nil;

    if ([hostPort hasPrefix:@"["]) {
        // IPv6 bracketed notation: [2001:db8::1]:443
        NSRange closeBracket = [hostPort rangeOfString:@"]"];
        if (closeBracket.location == NSNotFound) return NO;
        host = [hostPort substringWithRange:NSMakeRange(1, closeBracket.location - 1)];
        NSString *rest = [hostPort substringFromIndex:closeBracket.location + 1];
        if ([rest hasPrefix:@":"]) {
            portStr = [rest substringFromIndex:1];
        } else {
            return NO;
        }
    } else {
        NSRange lastColon = [hostPort rangeOfString:@":" options:NSBackwardsSearch];
        if (lastColon.location == NSNotFound) return NO;
        host = [hostPort substringToIndex:lastColon.location];
        portStr = [hostPort substringFromIndex:lastColon.location + 1];
    }

    NSInteger port = [portStr integerValue];
    if (host.length == 0 || port <= 0 || port > 65535) return NO;

    if (outHost) *outHost = host;
    if (outPort) *outPort = port;
    return YES;
}

static NSDictionary<NSString *, id> * _Nullable IPBuildTransportDict(NSString *netType,
                                                                     NSString *hostHeader,
                                                                     NSString *pathOrService,
                                                                     NSString *headerType) {
    NSString *type = [netType.lowercaseString stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (type.length == 0 || [type isEqualToString:@"tcp"] || [type isEqualToString:@"raw"] || [type isEqualToString:@"none"]) {
        if ([headerType.lowercaseString isEqualToString:@"http"]) {
            NSMutableDictionary *http = [NSMutableDictionary dictionary];
            http[@"type"] = @"http";
            if (hostHeader.length > 0) {
                http[@"host"] = [hostHeader componentsSeparatedByString:@","];
            }
            http[@"path"] = pathOrService.length > 0 ? pathOrService : @"/";
            return http;
        }
        return nil;
    }

    if ([type isEqualToString:@"ws"] || [type isEqualToString:@"websocket"]) {
        NSMutableDictionary *ws = [NSMutableDictionary dictionary];
        ws[@"type"] = @"ws";
        ws[@"path"] = pathOrService.length > 0 ? pathOrService : @"/";
        if (hostHeader.length > 0) {
            ws[@"headers"] = @{ @"Host" : hostHeader };
        }
        return ws;
    }

    if ([type isEqualToString:@"grpc"]) {
        NSMutableDictionary *grpc = [NSMutableDictionary dictionary];
        grpc[@"type"] = @"grpc";
        if (pathOrService.length > 0) {
            grpc[@"service_name"] = pathOrService;
        }
        return grpc;
    }

    if ([type isEqualToString:@"http"] || [type isEqualToString:@"h2"]) {
        NSMutableDictionary *http = [NSMutableDictionary dictionary];
        http[@"type"] = @"http";
        if (hostHeader.length > 0) {
            http[@"host"] = [hostHeader componentsSeparatedByString:@","];
        }
        http[@"path"] = pathOrService.length > 0 ? pathOrService : @"/";
        return http;
    }

    if ([type isEqualToString:@"httpupgrade"]) {
        NSMutableDictionary *hu = [NSMutableDictionary dictionary];
        hu[@"type"] = @"httpupgrade";
        if (hostHeader.length > 0) {
            hu[@"host"] = hostHeader;
        }
        hu[@"path"] = pathOrService.length > 0 ? pathOrService : @"/";
        return hu;
    }

    return nil;
}

static NSDictionary<NSString *, id> * _Nullable IPBuildTLSDict(BOOL enabled,
                                                               NSString *serverName,
                                                               BOOL insecure,
                                                               NSString *fingerprint,
                                                               NSString *alpnRaw,
                                                               BOOL isReality,
                                                               NSString *publicKey,
                                                               NSString *shortID) {
    if (!enabled && !isReality) {
        return nil;
    }

    NSMutableDictionary *tls = [NSMutableDictionary dictionary];
    tls[@"enabled"] = @YES;
    if (serverName.length > 0) {
        tls[@"server_name"] = serverName;
    }
    if (insecure) {
        tls[@"insecure"] = @YES;
    }
    if (alpnRaw.length > 0) {
        NSMutableArray<NSString *> *alpnList = [NSMutableArray array];
        for (NSString *item in [alpnRaw componentsSeparatedByString:@","]) {
            NSString *trimmed = [item stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            if (trimmed.length > 0) {
                [alpnList addObject:trimmed];
            }
        }
        if (alpnList.count > 0) {
            tls[@"alpn"] = alpnList;
        }
    }

    NSString *fp = fingerprint.length > 0 ? fingerprint : (isReality ? @"chrome" : @"");
    if (fp.length > 0) {
        tls[@"utls"] = @{
            @"enabled" : @YES,
            @"fingerprint" : fp
        };
    }

    if (isReality) {
        NSMutableDictionary *reality = [NSMutableDictionary dictionary];
        reality[@"enabled"] = @YES;
        if (publicKey.length > 0) {
            reality[@"public_key"] = publicKey;
        }
        if (shortID.length > 0) {
            reality[@"short_id"] = shortID;
        }
        tls[@"reality"] = reality;
    }

    return tls;
}

static NSString *IPMakeUniqueTag(NSString *preferredName, NSMutableSet<NSString *> *usedTags) {
    NSString *base = [preferredName stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (base.length == 0) {
        base = @"Server";
    }
    // Avoid colliding with reserved sing-box tags
    NSString *lower = base.lowercaseString;
    if ([lower isEqualToString:@"auto"] || [lower isEqualToString:@"proxy"] ||
        [lower isEqualToString:@"direct"] || [lower isEqualToString:@"block"] ||
        [lower isEqualToString:@"dns-out"]) {
        base = [NSString stringWithFormat:@"node-%@", base];
    }

    NSString *candidate = base;
    NSInteger suffix = 2;
    while ([usedTags containsObject:candidate]) {
        candidate = [NSString stringWithFormat:@"%@ #%ld", base, (long)suffix++];
    }
    [usedTags addObject:candidate];
    return candidate;
}

// MARK: - Model Implementations

@implementation IPProxySubscription

- (NSDictionary<NSString *, id> *)toDictionary {
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    dict[@"identifier"] = self.identifier ?: @"";
    dict[@"name"] = self.name ?: @"";
    dict[@"url"] = self.url ?: @"";
    dict[@"nodeCount"] = @(self.nodeCount);
    if (self.lastUpdated) {
        dict[@"lastUpdated"] = @([self.lastUpdated timeIntervalSince1970]);
    }
    if (self.lastError) {
        dict[@"lastError"] = self.lastError;
    }
    return dict;
}

+ (nullable instancetype)fromDictionary:(NSDictionary<NSString *, id> *)dict {
    if (![dict isKindOfClass:[NSDictionary class]]) return nil;
    NSString *url = dict[@"url"];
    if (![url isKindOfClass:[NSString class]] || url.length == 0) return nil;

    IPProxySubscription *sub = [[IPProxySubscription alloc] init];
    sub.identifier = [dict[@"identifier"] isKindOfClass:[NSString class]] ? dict[@"identifier"] : [NSUUID UUID].UUIDString;
    sub.name = [dict[@"name"] isKindOfClass:[NSString class]] ? dict[@"name"] : url;
    sub.url = url;
    sub.nodeCount = [dict[@"nodeCount"] integerValue];
    if ([dict[@"lastUpdated"] isKindOfClass:[NSNumber class]]) {
        sub.lastUpdated = [NSDate dateWithTimeIntervalSince1970:[dict[@"lastUpdated"] doubleValue]];
    }
    if ([dict[@"lastError"] isKindOfClass:[NSString class]]) {
        sub.lastError = dict[@"lastError"];
    }
    return sub;
}

@end

@implementation IPProxyNode

- (NSDictionary<NSString *, id> *)toDictionary {
    return @{
        @"tag" : self.tag ?: @"",
        @"displayName" : self.displayName ?: @"",
        @"protocol" : self.protocol ?: @"",
        @"server" : self.server ?: @"",
        @"port" : @(self.port),
        @"subscriptionID" : self.subscriptionID ?: @"",
        @"outboundConfig" : self.outboundConfig ?: @{}
    };
}

+ (nullable instancetype)fromDictionary:(NSDictionary<NSString *, id> *)dict {
    if (![dict isKindOfClass:[NSDictionary class]]) return nil;
    NSDictionary *outbound = dict[@"outboundConfig"];
    if (![outbound isKindOfClass:[NSDictionary class]] || outbound.count == 0) return nil;

    IPProxyNode *node = [[IPProxyNode alloc] init];
    node.tag = [dict[@"tag"] isKindOfClass:[NSString class]] ? dict[@"tag"] : @"Node";
    node.displayName = [dict[@"displayName"] isKindOfClass:[NSString class]] ? dict[@"displayName"] : node.tag;
    node.protocol = [dict[@"protocol"] isKindOfClass:[NSString class]] ? dict[@"protocol"] : @"unknown";
    node.server = [dict[@"server"] isKindOfClass:[NSString class]] ? dict[@"server"] : @"";
    node.port = [dict[@"port"] integerValue];
    node.subscriptionID = [dict[@"subscriptionID"] isKindOfClass:[NSString class]] ? dict[@"subscriptionID"] : @"";
    node.outboundConfig = outbound;
    return node;
}

@end

// MARK: - SubscriptionManager

@interface SubscriptionManager ()
@property (nonatomic, strong) NSMutableArray<IPProxySubscription *> *mutableSubscriptions;
@property (nonatomic, strong) NSMutableArray<IPProxyNode *> *mutableNodes;
@property (nonatomic, strong) dispatch_queue_t stateQueue;
@end

@implementation SubscriptionManager

+ (instancetype)sharedManager {
    static SubscriptionManager *manager = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        manager = [[SubscriptionManager alloc] init];
    });
    return manager;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _stateQueue = dispatch_queue_create("com.instaproxy.subscription.state", DISPATCH_QUEUE_SERIAL);
        _mutableSubscriptions = [NSMutableArray array];
        _mutableNodes = [NSMutableArray array];
        [self loadFromUserDefaults];
    }
    return self;
}

- (uint16_t)localProxyPort {
    return 10808;
}

- (uint16_t)clashAPIPort {
    return 19090;
}

- (BOOL)proxyEnabled {
    return [[NSUserDefaults standardUserDefaults] boolForKey:kUDKeyProxyEnabled];
}

- (void)setProxyEnabled:(BOOL)proxyEnabled {
    [[NSUserDefaults standardUserDefaults] setBool:proxyEnabled forKey:kUDKeyProxyEnabled];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

- (NSString *)selectedTag {
    NSString *tag = [[NSUserDefaults standardUserDefaults] stringForKey:kUDKeySelectedTag];
    return (tag.length > 0) ? tag : kInstaProxyAutoOutboundTag;
}

- (void)setSelectedTag:(NSString *)selectedTag {
    NSString *value = (selectedTag.length > 0) ? selectedTag : kInstaProxyAutoOutboundTag;
    [[NSUserDefaults standardUserDefaults] setObject:value forKey:kUDKeySelectedTag];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

- (NSArray<IPProxySubscription *> *)subscriptions {
    __block NSArray<IPProxySubscription *> *copy = nil;
    dispatch_sync(self.stateQueue, ^{
        copy = [self.mutableSubscriptions copy];
    });
    return copy ?: @[];
}

- (NSArray<IPProxyNode *> *)nodes {
    __block NSArray<IPProxyNode *> *copy = nil;
    dispatch_sync(self.stateQueue, ^{
        copy = [self.mutableNodes copy];
    });
    return copy ?: @[];
}

// MARK: - Persistence

- (void)loadFromUserDefaults {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSData *subsData = [ud dataForKey:kUDKeySubscriptions];
    if (subsData) {
        NSArray *arr = [NSJSONSerialization JSONObjectWithData:subsData options:0 error:nil];
        if ([arr isKindOfClass:[NSArray class]]) {
            for (NSDictionary *d in arr) {
                IPProxySubscription *sub = [IPProxySubscription fromDictionary:d];
                if (sub) [self.mutableSubscriptions addObject:sub];
            }
        }
    }

    NSData *nodesData = [ud dataForKey:kUDKeyNodes];
    if (nodesData) {
        NSArray *arr = [NSJSONSerialization JSONObjectWithData:nodesData options:0 error:nil];
        if ([arr isKindOfClass:[NSArray class]]) {
            for (NSDictionary *d in arr) {
                IPProxyNode *node = [IPProxyNode fromDictionary:d];
                if (node) [self.mutableNodes addObject:node];
            }
        }
    }
}

- (void)saveToUserDefaultsLocked {
    NSMutableArray *subsArr = [NSMutableArray arrayWithCapacity:self.mutableSubscriptions.count];
    for (IPProxySubscription *sub in self.mutableSubscriptions) {
        [subsArr addObject:[sub toDictionary]];
    }
    NSMutableArray *nodesArr = [NSMutableArray arrayWithCapacity:self.mutableNodes.count];
    for (IPProxyNode *node in self.mutableNodes) {
        [nodesArr addObject:[node toDictionary]];
    }

    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSData *subsData = [NSJSONSerialization dataWithJSONObject:subsArr options:0 error:nil];
    NSData *nodesData = [NSJSONSerialization dataWithJSONObject:nodesArr options:0 error:nil];
    if (subsData) [ud setObject:subsData forKey:kUDKeySubscriptions];
    if (nodesData) [ud setObject:nodesData forKey:kUDKeyNodes];
    [ud synchronize];
}

- (void)notifyChange {
    dispatch_async(dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter] postNotificationName:kInstaProxySubscriptionsDidChangeNotification object:self];
    });
}

// MARK: - Subscription CRUD & Fetching

- (void)addSubscriptionWithURL:(NSString *)urlString
                          name:(nullable NSString *)name
                    completion:(void (^)(IPProxySubscription * _Nullable, NSError * _Nullable))completion {
    NSString *trimmed = [urlString stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSURL *url = [NSURL URLWithString:trimmed];
    if (!url || (![url.scheme.lowercaseString isEqualToString:@"http"] && ![url.scheme.lowercaseString isEqualToString:@"https"])) {
        NSError *err = [NSError errorWithDomain:kInstaProxyErrorDomain
                                           code:1001
                                       userInfo:@{ NSLocalizedDescriptionKey : @"Некорректный URL подписки (требуется http:// или https://)." }];
        if (completion) {
            dispatch_async(dispatch_get_main_queue(), ^{ completion(nil, err); });
        }
        return;
    }

    IPProxySubscription *sub = [[IPProxySubscription alloc] init];
    sub.identifier = [NSUUID UUID].UUIDString;
    sub.url = trimmed;
    NSString *trimmedName = [name stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    sub.name = (trimmedName.length > 0) ? trimmedName : (url.host ?: @"Подписка");

    [self fetchAndParseURL:url subscriptionID:sub.identifier completion:^(NSArray<IPProxyNode *> * _Nullable parsedNodes, NSError * _Nullable err) {
        if (err) {
            if (completion) {
                dispatch_async(dispatch_get_main_queue(), ^{ completion(nil, err); });
            }
            return;
        }

        dispatch_async(self.stateQueue, ^{
            sub.nodeCount = parsedNodes.count;
            sub.lastUpdated = [NSDate date];
            sub.lastError = nil;

            [self.mutableSubscriptions addObject:sub];
            [self replaceNodesForSubscriptionLocked:sub.identifier withNodes:parsedNodes];
            [self saveToUserDefaultsLocked];
            [self notifyChange];

            if (completion) {
                dispatch_async(dispatch_get_main_queue(), ^{ completion(sub, nil); });
            }
        });
    }];
}

- (void)removeSubscriptionWithIdentifier:(NSString *)identifier {
    if (identifier.length == 0) return;
    dispatch_async(self.stateQueue, ^{
        NSIndexSet *subIndexes = [self.mutableSubscriptions indexesOfObjectsPassingTest:^BOOL(IPProxySubscription *obj, NSUInteger idx, BOOL *stop) {
            return [obj.identifier isEqualToString:identifier];
        }];
        [self.mutableSubscriptions removeObjectsAtIndexes:subIndexes];

        NSIndexSet *nodeIndexes = [self.mutableNodes indexesOfObjectsPassingTest:^BOOL(IPProxyNode *obj, NSUInteger idx, BOOL *stop) {
            return [obj.subscriptionID isEqualToString:identifier];
        }];
        [self.mutableNodes removeObjectsAtIndexes:nodeIndexes];

        // Reset selected tag to auto if the selected node was deleted
        NSString *currentSelected = self.selectedTag;
        if (![currentSelected isEqualToString:kInstaProxyAutoOutboundTag]) {
            BOOL stillExists = NO;
            for (IPProxyNode *node in self.mutableNodes) {
                if ([node.tag isEqualToString:currentSelected]) {
                    stillExists = YES;
                    break;
                }
            }
            if (!stillExists) {
                self.selectedTag = kInstaProxyAutoOutboundTag;
            }
        }

        [self saveToUserDefaultsLocked];
        [self notifyChange];
    });
}

- (void)updateSubscriptionWithIdentifier:(NSString *)identifier
                              completion:(void (^)(BOOL, NSError * _Nullable))completion {
    __block IPProxySubscription *target = nil;
    dispatch_sync(self.stateQueue, ^{
        for (IPProxySubscription *sub in self.mutableSubscriptions) {
            if ([sub.identifier isEqualToString:identifier]) {
                target = sub;
                break;
            }
        }
    });

    if (!target) {
        NSError *err = [NSError errorWithDomain:kInstaProxyErrorDomain
                                           code:1002
                                       userInfo:@{ NSLocalizedDescriptionKey : @"Подписка не найдена." }];
        if (completion) dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, err); });
        return;
    }

    NSURL *url = [NSURL URLWithString:target.url];
    [self fetchAndParseURL:url subscriptionID:target.identifier completion:^(NSArray<IPProxyNode *> * _Nullable parsedNodes, NSError * _Nullable err) {
        dispatch_async(self.stateQueue, ^{
            if (err) {
                target.lastError = err.localizedDescription;
                [self saveToUserDefaultsLocked];
                [self notifyChange];
                if (completion) dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, err); });
                return;
            }

            target.nodeCount = parsedNodes.count;
            target.lastUpdated = [NSDate date];
            target.lastError = nil;
            [self replaceNodesForSubscriptionLocked:target.identifier withNodes:parsedNodes];
            [self saveToUserDefaultsLocked];
            [self notifyChange];
            if (completion) dispatch_async(dispatch_get_main_queue(), ^{ completion(YES, nil); });
        });
    }];
}

- (void)updateAllSubscriptionsWithCompletion:(void (^)(NSInteger, NSInteger, NSError * _Nullable))completion {
    NSArray<IPProxySubscription *> *subs = self.subscriptions;
    if (subs.count == 0) {
        if (completion) dispatch_async(dispatch_get_main_queue(), ^{ completion(0, 0, nil); });
        return;
    }

    dispatch_group_t group = dispatch_group_create();
    __block NSInteger updatedCount = 0;
    __block NSInteger failedCount = 0;
    __block NSError *lastError = nil;
    NSLock *counterLock = [[NSLock alloc] init];

    for (IPProxySubscription *sub in subs) {
        dispatch_group_enter(group);
        [self updateSubscriptionWithIdentifier:sub.identifier completion:^(BOOL success, NSError * _Nullable error) {
            [counterLock lock];
            if (success) {
                updatedCount++;
            } else {
                failedCount++;
                if (error) lastError = error;
            }
            [counterLock unlock];
            dispatch_group_leave(group);
        }];
    }

    dispatch_group_notify(group, dispatch_get_main_queue(), ^{
        if (completion) {
            completion(updatedCount, failedCount, lastError);
        }
    });
}

- (void)replaceNodesForSubscriptionLocked:(NSString *)subscriptionID withNodes:(NSArray<IPProxyNode *> *)newNodes {
    NSIndexSet *oldIndexes = [self.mutableNodes indexesOfObjectsPassingTest:^BOOL(IPProxyNode *obj, NSUInteger idx, BOOL *stop) {
        return [obj.subscriptionID isEqualToString:subscriptionID];
    }];
    [self.mutableNodes removeObjectsAtIndexes:oldIndexes];

    // Ensure global tag uniqueness across all subscriptions
    NSMutableSet<NSString *> *usedTags = [NSMutableSet set];
    for (IPProxyNode *existing in self.mutableNodes) {
        [usedTags addObject:existing.tag];
    }

    for (IPProxyNode *node in newNodes) {
        NSString *uniqueTag = IPMakeUniqueTag(node.tag, usedTags);
        node.tag = uniqueTag;
        NSMutableDictionary *cfg = [node.outboundConfig mutableCopy];
        cfg[@"tag"] = uniqueTag;
        node.outboundConfig = [cfg copy];
        [self.mutableNodes addObject:node];
    }
}

- (void)fetchAndParseURL:(NSURL *)url
          subscriptionID:(NSString *)subscriptionID
              completion:(void (^)(NSArray<IPProxyNode *> * _Nullable nodes, NSError * _Nullable error))completion {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        // Resolve subscription server IPs and temporarily bypass interception so download works even if proxy is dead
        NSSet<NSString *> *hostIPs = url.host.length > 0 ? [SubscriptionManager resolveHostToIPAddresses:url.host] : [NSSet set];
        if (hostIPs.count > 0) {
            [[ProxyInterceptor sharedInterceptor] addTemporaryBypassIPAddresses:hostIPs];
        }

        NSURLSessionConfiguration *config = [ProxyInterceptor directSessionConfiguration];
        config.timeoutIntervalForRequest = 20.0;
        config.timeoutIntervalForResource = 30.0;
        config.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;

        NSURLSession *session = [NSURLSession sessionWithConfiguration:config];
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
        req.HTTPMethod = @"GET";
        [req setValue:@"sing-box/1.11.0 (InstaProxy iOS)" forHTTPHeaderField:@"User-Agent"];

        NSURLSessionDataTask *task = [session dataTaskWithRequest:req completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable netErr) {
            if (hostIPs.count > 0) {
                [[ProxyInterceptor sharedInterceptor] removeTemporaryBypassIPAddresses:hostIPs];
            }
            [session finishTasksAndInvalidate];

            if (netErr) {
                completion(nil, netErr);
                return;
            }
            if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
                NSInteger status = ((NSHTTPURLResponse *)response).statusCode;
                if (status < 200 || status >= 300) {
                    NSError *httpErr = [NSError errorWithDomain:kInstaProxyErrorDomain
                                                           code:status
                                                       userInfo:@{ NSLocalizedDescriptionKey : [NSString stringWithFormat:@"HTTP ошибка %ld при загрузке подписки.", (long)status] }];
                    completion(nil, httpErr);
                    return;
                }
            }
            if (!data || data.length == 0) {
                NSError *emptyErr = [NSError errorWithDomain:kInstaProxyErrorDomain
                                                        code:1003
                                                    userInfo:@{ NSLocalizedDescriptionKey : @"Сервер вернул пустую подписку." }];
                completion(nil, emptyErr);
                return;
            }

            NSError *parseErr = nil;
            NSArray<IPProxyNode *> *nodes = [self parseSubscriptionData:data subscriptionID:subscriptionID error:&parseErr];
            if (nodes.count == 0) {
                NSError *finalErr = parseErr ?: [NSError errorWithDomain:kInstaProxyErrorDomain
                                                                    code:1004
                                                                userInfo:@{ NSLocalizedDescriptionKey : @"В подписке не найдено поддерживаемых серверов (vless, trojan, ss, vmess, sing-box JSON)." }];
                completion(nil, finalErr);
                return;
            }
            completion(nodes, nil);
        }];
        [task resume];
    });
}

// MARK: - Protocol & Direct JSON Parsers

- (NSArray<IPProxyNode *> *)parseSubscriptionData:(NSData *)data
                                   subscriptionID:(NSString *)subscriptionID
                                            error:(NSError * _Nullable * _Nullable)error {
    NSString *rawText = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!rawText) {
        rawText = [[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding];
    }
    if (!rawText) {
        if (error) {
            *error = [NSError errorWithDomain:kInstaProxyErrorDomain
                                         code:1005
                                     userInfo:@{ NSLocalizedDescriptionKey : @"Не удалось декодировать текст подписки." }];
        }
        return @[];
    }

    NSString *trimmed = [rawText stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

    // 1. Direct sing-box JSON support
    if ([trimmed hasPrefix:@"{"] || [trimmed hasPrefix:@"["]) {
        NSError *jsonErr = nil;
        id jsonObj = [NSJSONSerialization JSONObjectWithData:[trimmed dataUsingEncoding:NSUTF8StringEncoding]
                                                     options:0
                                                       error:&jsonErr];
        if (!jsonErr && jsonObj) {
            NSArray<IPProxyNode *> *jsonNodes = [self parseDirectSingBoxJSON:jsonObj subscriptionID:subscriptionID];
            if (jsonNodes.count > 0) {
                return jsonNodes;
            }
        }
    }

    // 2. Plain URI list or Base64-encoded URI list
    NSString *uriText = trimmed;
    BOOL looksLikeURIList = ([trimmed rangeOfString:@"vless://"].location != NSNotFound ||
                             [trimmed rangeOfString:@"trojan://"].location != NSNotFound ||
                             [trimmed rangeOfString:@"ss://"].location != NSNotFound ||
                             [trimmed rangeOfString:@"vmess://"].location != NSNotFound);

    if (!looksLikeURIList) {
        NSData *decodedData = IPDecodeFlexibleBase64(trimmed);
        if (decodedData.length > 0) {
            NSString *decodedStr = [[NSString alloc] initWithData:decodedData encoding:NSUTF8StringEncoding];
            if (decodedStr.length > 0) {
                NSString *decodedTrimmed = [decodedStr stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
                // Some subscriptions Base64-encode a sing-box JSON config
                if ([decodedTrimmed hasPrefix:@"{"]) {
                    id jsonObj = [NSJSONSerialization JSONObjectWithData:decodedData options:0 error:nil];
                    if (jsonObj) {
                        NSArray<IPProxyNode *> *jsonNodes = [self parseDirectSingBoxJSON:jsonObj subscriptionID:subscriptionID];
                        if (jsonNodes.count > 0) return jsonNodes;
                    }
                }
                uriText = decodedTrimmed;
            }
        }
    }

    NSMutableArray<IPProxyNode *> *nodes = [NSMutableArray array];
    NSMutableSet<NSString *> *usedTags = [NSMutableSet set];
    NSArray<NSString *> *lines = [uriText componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];

    for (NSString *rawLine in lines) {
        NSString *line = [rawLine stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (line.length == 0 || [line hasPrefix:@"#"]) continue;

        IPProxyNode *node = nil;
        if ([line.lowercaseString hasPrefix:@"vless://"]) {
            node = [self parseVLESSURI:line subscriptionID:subscriptionID usedTags:usedTags];
        } else if ([line.lowercaseString hasPrefix:@"trojan://"]) {
            node = [self parseTrojanURI:line subscriptionID:subscriptionID usedTags:usedTags];
        } else if ([line.lowercaseString hasPrefix:@"ss://"]) {
            node = [self parseShadowsocksURI:line subscriptionID:subscriptionID usedTags:usedTags];
        } else if ([line.lowercaseString hasPrefix:@"vmess://"]) {
            node = [self parseVMessURI:line subscriptionID:subscriptionID usedTags:usedTags];
        }

        if (node) {
            [nodes addObject:node];
        }
    }

    return nodes;
}

- (NSArray<IPProxyNode *> *)parseDirectSingBoxJSON:(id)jsonObj subscriptionID:(NSString *)subscriptionID {
    NSArray *outbounds = nil;
    if ([jsonObj isKindOfClass:[NSDictionary class]]) {
        id ob = ((NSDictionary *)jsonObj)[@"outbounds"];
        if ([ob isKindOfClass:[NSArray class]]) {
            outbounds = ob;
        }
    } else if ([jsonObj isKindOfClass:[NSArray class]]) {
        outbounds = jsonObj;
    }

    if (!outbounds) return @[];

    NSSet<NSString *> *skipTypes = [NSSet setWithArray:@[ @"direct", @"block", @"dns", @"selector", @"urltest" ]];
    NSMutableArray<IPProxyNode *> *result = [NSMutableArray array];
    NSMutableSet<NSString *> *usedTags = [NSMutableSet set];

    for (id item in outbounds) {
        if (![item isKindOfClass:[NSDictionary class]]) continue;
        NSDictionary *obDict = (NSDictionary *)item;
        NSString *type = [obDict[@"type"] isKindOfClass:[NSString class]] ? ((NSString *)obDict[@"type"]).lowercaseString : @"";
        if (type.length == 0 || [skipTypes containsObject:type]) continue;

        NSString *server = [obDict[@"server"] isKindOfClass:[NSString class]] ? obDict[@"server"] : @"";
        NSInteger port = [obDict[@"server_port"] integerValue];
        NSString *rawTag = [obDict[@"tag"] isKindOfClass:[NSString class]] ? obDict[@"tag"] : [NSString stringWithFormat:@"%@-%@", type, server];
        NSString *tag = IPMakeUniqueTag(rawTag, usedTags);

        NSMutableDictionary *cleanOutbound = [obDict mutableCopy];
        cleanOutbound[@"tag"] = tag;

        IPProxyNode *node = [[IPProxyNode alloc] init];
        node.tag = tag;
        node.displayName = rawTag.length > 0 ? rawTag : tag;
        node.protocol = type;
        node.server = server;
        node.port = port;
        node.subscriptionID = subscriptionID;
        node.outboundConfig = [cleanOutbound copy];
        [result addObject:node];
    }

    return result;
}

- (nullable IPProxyNode *)parseVLESSURI:(NSString *)uri
                         subscriptionID:(NSString *)subscriptionID
                               usedTags:(NSMutableSet<NSString *> *)usedTags {
    NSString *body = [uri substringFromIndex:8]; // strip "vless://"
    NSString *remark = @"";
    NSRange hashRange = [body rangeOfString:@"#"];
    if (hashRange.location != NSNotFound) {
        remark = IPPercentDecode([body substringFromIndex:hashRange.location + 1]);
        body = [body substringToIndex:hashRange.location];
    }

    NSString *query = @"";
    NSRange qRange = [body rangeOfString:@"?"];
    if (qRange.location != NSNotFound) {
        query = [body substringFromIndex:qRange.location + 1];
        body = [body substringToIndex:qRange.location];
    }

    NSRange atRange = [body rangeOfString:@"@"];
    if (atRange.location == NSNotFound) return nil;
    NSString *uuid = IPPercentDecode([body substringToIndex:atRange.location]);
    NSString *hostPort = [body substringFromIndex:atRange.location + 1];
    if (uuid.length == 0) return nil;

    NSString *server = nil;
    NSInteger port = 0;
    if (!IPParseHostAndPort(hostPort, &server, &port)) return nil;

    NSDictionary<NSString *, NSString *> *params = IPParseQueryParameters(query);
    NSString *security = (params[@"security"] ?: @"none").lowercaseString;
    NSString *sni = params[@"sni"].length > 0 ? params[@"sni"] : (params[@"peer"].length > 0 ? params[@"peer"] : server);
    NSString *fp = params[@"fp"] ?: @"";
    NSString *alpn = params[@"alpn"] ?: @"";
    NSString *pbk = params[@"pbk"] ?: @"";
    NSString *sid = params[@"sid"] ?: @"";
    NSString *flow = params[@"flow"] ?: @"";
    NSString *netType = params[@"type"] ?: @"tcp";
    NSString *hostHeader = params[@"host"] ?: @"";
    NSString *pathOrSvc = [netType.lowercaseString isEqualToString:@"grpc"] ? (params[@"serviceName"] ?: params[@"path"] ?: @"") : (params[@"path"] ?: @"/");
    NSString *headerType = params[@"headerType"] ?: @"";
    BOOL insecure = [params[@"allowInsecure"] isEqualToString:@"1"] || [params[@"allowInsecure"].lowercaseString isEqualToString:@"true"] || [params[@"insecure"] isEqualToString:@"1"];

    BOOL isReality = [security isEqualToString:@"reality"];
    BOOL isTLS = [security isEqualToString:@"tls"] || isReality;

    NSString *displayName = remark.length > 0 ? remark : [NSString stringWithFormat:@"VLESS %@:%ld", server, (long)port];
    NSString *tag = IPMakeUniqueTag(displayName, usedTags);

    NSMutableDictionary *outbound = [NSMutableDictionary dictionary];
    outbound[@"type"] = @"vless";
    outbound[@"tag"] = tag;
    outbound[@"server"] = server;
    outbound[@"server_port"] = @(port);
    outbound[@"uuid"] = uuid;
    outbound[@"packet_encoding"] = @"xudp";
    if (flow.length > 0) {
        outbound[@"flow"] = flow;
    }

    NSDictionary *tls = IPBuildTLSDict(isTLS, sni, insecure, fp, alpn, isReality, pbk, sid);
    if (tls) outbound[@"tls"] = tls;

    NSDictionary *transport = IPBuildTransportDict(netType, hostHeader, pathOrSvc, headerType);
    if (transport) outbound[@"transport"] = transport;

    IPProxyNode *node = [[IPProxyNode alloc] init];
    node.tag = tag;
    node.displayName = displayName;
    node.protocol = @"vless";
    node.server = server;
    node.port = port;
    node.subscriptionID = subscriptionID;
    node.outboundConfig = [outbound copy];
    return node;
}

- (nullable IPProxyNode *)parseTrojanURI:(NSString *)uri
                          subscriptionID:(NSString *)subscriptionID
                                usedTags:(NSMutableSet<NSString *> *)usedTags {
    NSString *body = [uri substringFromIndex:9]; // strip "trojan://"
    NSString *remark = @"";
    NSRange hashRange = [body rangeOfString:@"#"];
    if (hashRange.location != NSNotFound) {
        remark = IPPercentDecode([body substringFromIndex:hashRange.location + 1]);
        body = [body substringToIndex:hashRange.location];
    }

    NSString *query = @"";
    NSRange qRange = [body rangeOfString:@"?"];
    if (qRange.location != NSNotFound) {
        query = [body substringFromIndex:qRange.location + 1];
        body = [body substringToIndex:qRange.location];
    }

    NSRange atRange = [body rangeOfString:@"@"];
    if (atRange.location == NSNotFound) return nil;
    NSString *password = IPPercentDecode([body substringToIndex:atRange.location]);
    NSString *hostPort = [body substringFromIndex:atRange.location + 1];
    if (password.length == 0) return nil;

    NSString *server = nil;
    NSInteger port = 0;
    if (!IPParseHostAndPort(hostPort, &server, &port)) return nil;

    NSDictionary<NSString *, NSString *> *params = IPParseQueryParameters(query);
    NSString *security = (params[@"security"] ?: @"tls").lowercaseString;
    NSString *sni = params[@"sni"].length > 0 ? params[@"sni"] : (params[@"peer"].length > 0 ? params[@"peer"] : server);
    NSString *fp = params[@"fp"] ?: @"";
    NSString *alpn = params[@"alpn"] ?: @"";
    NSString *pbk = params[@"pbk"] ?: @"";
    NSString *sid = params[@"sid"] ?: @"";
    NSString *netType = params[@"type"] ?: @"tcp";
    NSString *hostHeader = params[@"host"] ?: @"";
    NSString *pathOrSvc = [netType.lowercaseString isEqualToString:@"grpc"] ? (params[@"serviceName"] ?: params[@"path"] ?: @"") : (params[@"path"] ?: @"/");
    NSString *headerType = params[@"headerType"] ?: @"";
    BOOL insecure = [params[@"allowInsecure"] isEqualToString:@"1"] || [params[@"allowInsecure"].lowercaseString isEqualToString:@"true"] || [params[@"insecure"] isEqualToString:@"1"];

    BOOL isReality = [security isEqualToString:@"reality"];
    BOOL isTLS = ![security isEqualToString:@"none"];

    NSString *displayName = remark.length > 0 ? remark : [NSString stringWithFormat:@"Trojan %@:%ld", server, (long)port];
    NSString *tag = IPMakeUniqueTag(displayName, usedTags);

    NSMutableDictionary *outbound = [NSMutableDictionary dictionary];
    outbound[@"type"] = @"trojan";
    outbound[@"tag"] = tag;
    outbound[@"server"] = server;
    outbound[@"server_port"] = @(port);
    outbound[@"password"] = password;

    NSDictionary *tls = IPBuildTLSDict(isTLS, sni, insecure, fp, alpn, isReality, pbk, sid);
    if (tls) outbound[@"tls"] = tls;

    NSDictionary *transport = IPBuildTransportDict(netType, hostHeader, pathOrSvc, headerType);
    if (transport) outbound[@"transport"] = transport;

    IPProxyNode *node = [[IPProxyNode alloc] init];
    node.tag = tag;
    node.displayName = displayName;
    node.protocol = @"trojan";
    node.server = server;
    node.port = port;
    node.subscriptionID = subscriptionID;
    node.outboundConfig = [outbound copy];
    return node;
}

- (nullable IPProxyNode *)parseShadowsocksURI:(NSString *)uri
                               subscriptionID:(NSString *)subscriptionID
                                     usedTags:(NSMutableSet<NSString *> *)usedTags {
    NSString *body = [uri substringFromIndex:5]; // strip "ss://"
    NSString *remark = @"";
    NSRange hashRange = [body rangeOfString:@"#"];
    if (hashRange.location != NSNotFound) {
        remark = IPPercentDecode([body substringFromIndex:hashRange.location + 1]);
        body = [body substringToIndex:hashRange.location];
    }

    NSString *query = @"";
    NSRange qRange = [body rangeOfString:@"?"];
    if (qRange.location != NSNotFound) {
        query = [body substringFromIndex:qRange.location + 1];
        body = [body substringToIndex:qRange.location];
    }

    NSString *method = nil;
    NSString *password = nil;
    NSString *server = nil;
    NSInteger port = 0;

    NSRange atRange = [body rangeOfString:@"@" options:NSBackwardsSearch];
    if (atRange.location != NSNotFound) {
        // SIP002 format: ss://base64(method:password)@host:port OR ss://method:password@host:port
        NSString *userInfoRaw = IPPercentDecode([body substringToIndex:atRange.location]);
        NSString *hostPort = [body substringFromIndex:atRange.location + 1];
        if (!IPParseHostAndPort(hostPort, &server, &port)) return nil;

        NSString *userInfo = userInfoRaw;
        if ([userInfo rangeOfString:@":"].location == NSNotFound) {
            NSData *decoded = IPDecodeFlexibleBase64(userInfoRaw);
            if (decoded) {
                userInfo = [[NSString alloc] initWithData:decoded encoding:NSUTF8StringEncoding];
            }
        }
        NSRange colon = [userInfo rangeOfString:@":"];
        if (colon.location == NSNotFound) return nil;
        method = [userInfo substringToIndex:colon.location];
        password = [userInfo substringFromIndex:colon.location + 1];
    } else {
        // Legacy format: ss://base64(method:password@host:port)
        NSData *decoded = IPDecodeFlexibleBase64(body);
        if (!decoded) return nil;
        NSString *decodedStr = [[NSString alloc] initWithData:decoded encoding:NSUTF8StringEncoding];
        if (!decodedStr) return nil;
        NSRange decAt = [decodedStr rangeOfString:@"@" options:NSBackwardsSearch];
        if (decAt.location == NSNotFound) return nil;

        NSString *userInfo = [decodedStr substringToIndex:decAt.location];
        NSString *hostPort = [decodedStr substringFromIndex:decAt.location + 1];
        if (!IPParseHostAndPort(hostPort, &server, &port)) return nil;

        NSRange colon = [userInfo rangeOfString:@":"];
        if (colon.location == NSNotFound) return nil;
        method = [userInfo substringToIndex:colon.location];
        password = [userInfo substringFromIndex:colon.location + 1];
    }

    if (method.length == 0 || password.length == 0) return nil;

    NSString *displayName = remark.length > 0 ? remark : [NSString stringWithFormat:@"SS %@:%ld", server, (long)port];
    NSString *tag = IPMakeUniqueTag(displayName, usedTags);

    NSMutableDictionary *outbound = [NSMutableDictionary dictionary];
    outbound[@"type"] = @"shadowsocks";
    outbound[@"tag"] = tag;
    outbound[@"server"] = server;
    outbound[@"server_port"] = @(port);
    outbound[@"method"] = method;
    outbound[@"password"] = password;

    NSDictionary<NSString *, NSString *> *params = IPParseQueryParameters(query);
    NSString *pluginRaw = params[@"plugin"];
    if (pluginRaw.length > 0) {
        NSRange semi = [pluginRaw rangeOfString:@";"];
        if (semi.location != NSNotFound) {
            NSString *pluginName = [pluginRaw substringToIndex:semi.location];
            NSString *pluginOpts = [pluginRaw substringFromIndex:semi.location + 1];
            if ([pluginName isEqualToString:@"simple-obfs"]) {
                pluginName = @"obfs-local";
            }
            outbound[@"plugin"] = pluginName;
            outbound[@"plugin_opts"] = pluginOpts;
        } else {
            outbound[@"plugin"] = pluginRaw;
        }
    }

    IPProxyNode *node = [[IPProxyNode alloc] init];
    node.tag = tag;
    node.displayName = displayName;
    node.protocol = @"shadowsocks";
    node.server = server;
    node.port = port;
    node.subscriptionID = subscriptionID;
    node.outboundConfig = [outbound copy];
    return node;
}

- (nullable IPProxyNode *)parseVMessURI:(NSString *)uri
                         subscriptionID:(NSString *)subscriptionID
                               usedTags:(NSMutableSet<NSString *> *)usedTags {
    NSString *b64 = [uri substringFromIndex:8]; // strip "vmess://"
    NSData *jsonData = IPDecodeFlexibleBase64(b64);
    if (!jsonData) return nil;

    NSDictionary *payload = [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:nil];
    if (![payload isKindOfClass:[NSDictionary class]]) return nil;

    NSString *server = [payload[@"add"] isKindOfClass:[NSString class]] ? payload[@"add"] : @"";
    NSInteger port = [payload[@"port"] integerValue];
    NSString *uuid = [payload[@"id"] isKindOfClass:[NSString class]] ? payload[@"id"] : @"";
    if (server.length == 0 || port <= 0 || port > 65535 || uuid.length == 0) return nil;

    NSInteger alterID = [payload[@"aid"] integerValue];
    NSString *security = [payload[@"scy"] isKindOfClass:[NSString class]] && ((NSString *)payload[@"scy"]).length > 0
        ? payload[@"scy"] : @"auto";
    NSString *netType = [payload[@"net"] isKindOfClass:[NSString class]] ? payload[@"net"] : @"tcp";
    NSString *headerType = [payload[@"type"] isKindOfClass:[NSString class]] ? payload[@"type"] : @"";
    NSString *hostHeader = [payload[@"host"] isKindOfClass:[NSString class]] ? payload[@"host"] : @"";
    NSString *pathOrSvc = [payload[@"path"] isKindOfClass:[NSString class]] ? payload[@"path"] : @"/";
    NSString *tlsFlag = [payload[@"tls"] isKindOfClass:[NSString class]] ? ((NSString *)payload[@"tls"]).lowercaseString : @"";
    BOOL isTLS = [tlsFlag isEqualToString:@"tls"] || [tlsFlag isEqualToString:@"1"] || [tlsFlag isEqualToString:@"true"];
    NSString *sni = [payload[@"sni"] isKindOfClass:[NSString class]] && ((NSString *)payload[@"sni"]).length > 0
        ? payload[@"sni"] : (hostHeader.length > 0 ? hostHeader : server);
    NSString *alpn = [payload[@"alpn"] isKindOfClass:[NSString class]] ? payload[@"alpn"] : @"";
    NSString *fp = [payload[@"fp"] isKindOfClass:[NSString class]] ? payload[@"fp"] : @"";
    NSString *ps = [payload[@"ps"] isKindOfClass:[NSString class]] ? payload[@"ps"] : @"";
    BOOL insecure = ([payload[@"skip-cert-verify"] boolValue] || [payload[@"allowInsecure"] boolValue]);

    NSString *displayName = ps.length > 0 ? ps : [NSString stringWithFormat:@"VMess %@:%ld", server, (long)port];
    NSString *tag = IPMakeUniqueTag(displayName, usedTags);

    NSMutableDictionary *outbound = [NSMutableDictionary dictionary];
    outbound[@"type"] = @"vmess";
    outbound[@"tag"] = tag;
    outbound[@"server"] = server;
    outbound[@"server_port"] = @(port);
    outbound[@"uuid"] = uuid;
    outbound[@"security"] = security;
    outbound[@"alter_id"] = @(alterID);

    NSDictionary *tls = IPBuildTLSDict(isTLS, sni, insecure, fp, alpn, NO, @"", @"");
    if (tls) outbound[@"tls"] = tls;

    NSDictionary *transport = IPBuildTransportDict(netType, hostHeader, pathOrSvc, headerType);
    if (transport) outbound[@"transport"] = transport;

    IPProxyNode *node = [[IPProxyNode alloc] init];
    node.tag = tag;
    node.displayName = displayName;
    node.protocol = @"vmess";
    node.server = server;
    node.port = port;
    node.subscriptionID = subscriptionID;
    node.outboundConfig = [outbound copy];
    return node;
}

// MARK: - Sing-box Config Generation

- (nullable NSString *)generateSingBoxConfigJSONWithError:(NSError * _Nullable * _Nullable)error {
    NSArray<IPProxyNode *> *allNodes = self.nodes;
    if (allNodes.count == 0) {
        if (error) {
            *error = [NSError errorWithDomain:kInstaProxyErrorDomain
                                         code:2001
                                     userInfo:@{ NSLocalizedDescriptionKey : @"Нет доступных серверов. Добавьте URL подписки." }];
        }
        return nil;
    }

    NSMutableArray<NSString *> *nodeTags = [NSMutableArray arrayWithCapacity:allNodes.count];
    NSMutableArray<NSDictionary *> *outbounds = [NSMutableArray array];

    for (IPProxyNode *node in allNodes) {
        [nodeTags addObject:node.tag];
    }

    NSString *desiredDefault = self.selectedTag;
    BOOL validSelection = [desiredDefault isEqualToString:kInstaProxyAutoOutboundTag] || [nodeTags containsObject:desiredDefault];
    if (!validSelection) {
        desiredDefault = kInstaProxyAutoOutboundTag;
    }

    NSMutableArray<NSString *> *selectorChoices = [NSMutableArray arrayWithObject:kInstaProxyAutoOutboundTag];
    [selectorChoices addObjectsFromArray:nodeTags];

    // 1. Selector outbound (switches between "auto" urltest and any specific node)
    [outbounds addObject:@{
        @"type" : @"selector",
        @"tag" : kInstaProxySelectorOutboundTag,
        @"outbounds" : selectorChoices,
        @"default" : desiredDefault,
        @"interrupt_exist_connections" : @YES
    }];

    // 2. URLTest outbound (automatic fastest server selection for Instagram)
    [outbounds addObject:@{
        @"type" : @"urltest",
        @"tag" : kInstaProxyAutoOutboundTag,
        @"outbounds" : nodeTags,
        @"url" : @"https://www.instagram.com/robots.txt",
        @"interval" : @"5m",
        @"tolerance" : @50,
        @"interrupt_exist_connections" : @NO
    }];

    // 3. Individual proxy server outbounds
    for (IPProxyNode *node in allNodes) {
        [outbounds addObject:node.outboundConfig];
    }

    // 4. Utility outbounds
    [outbounds addObject:@{ @"type" : @"direct", @"tag" : @"direct" }];
    [outbounds addObject:@{ @"type" : @"block", @"tag" : @"block" }];

    NSDictionary *config = @{
        @"log" : @{
            @"level" : @"info",
            @"timestamp" : @YES
        },
        @"dns" : @{
            @"servers" : @[
                @{
                    @"tag" : @"dns-direct",
                    @"address" : @"1.1.1.1",
                    @"detour" : @"direct"
                },
                @{
                    @"tag" : @"dns-remote",
                    @"address" : @"https://1.1.1.1/dns-query",
                    @"address_resolver" : @"dns-direct",
                    @"detour" : kInstaProxySelectorOutboundTag
                }
            ],
            @"strategy" : @"prefer_ipv4",
            @"final" : @"dns-direct"
        },
        @"inbounds" : @[
            @{
                @"type" : @"mixed",
                @"tag" : @"mixed-in",
                @"listen" : @"127.0.0.1",
                @"listen_port" : @(self.localProxyPort),
                @"sniff" : @YES,
                @"sniff_override_destination" : @NO
            },
            @{
                @"type" : @"mixed",
                @"tag" : @"mixed-in-v6",
                @"listen" : @"::1",
                @"listen_port" : @(self.localProxyPort),
                @"sniff" : @YES,
                @"sniff_override_destination" : @NO
            }
        ],
        @"outbounds" : outbounds,
        @"route" : @{
            @"rules" : @[
                @{ @"ip_is_private" : @YES, @"outbound" : @"direct" }
            ],
            @"final" : kInstaProxySelectorOutboundTag,
            @"auto_detect_interface" : @NO
        },
        @"experimental" : @{
            @"clash_api" : @{
                @"external_controller" : [NSString stringWithFormat:@"127.0.0.1:%u", self.clashAPIPort]
            }
        }
    };

    NSError *serErr = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:config options:NSJSONWritingPrettyPrinted error:&serErr];
    if (serErr || !jsonData) {
        if (error) *error = serErr;
        return nil;
    }

    return [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
}

// MARK: - DNS Resolution for Loop-Free Bypass

+ (NSSet<NSString *> *)resolveHostToIPAddresses:(NSString *)host {
    NSMutableSet<NSString *> *results = [NSMutableSet set];
    if (!host || host.length == 0) return results;

    const char *cHost = host.UTF8String;
    if (!cHost) return results;

    // Fast path: literal IPv4 or IPv6
    struct in_addr v4{};
    if (inet_pton(AF_INET, cHost, &v4) == 1) {
        [results addObject:host];
        return results;
    }
    struct in6_addr v6{};
    if (inet_pton(AF_INET6, cHost, &v6) == 1) {
        [results addObject:host];
        return results;
    }

    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = nullptr;
    if (getaddrinfo(cHost, nullptr, &hints, &res) == 0 && res != nullptr) {
        char buf[INET6_ADDRSTRLEN] = {0};
        for (struct addrinfo *p = res; p != nullptr; p = p->ai_next) {
            if (p->ai_family == AF_INET) {
                auto *sin = reinterpret_cast<struct sockaddr_in *>(p->ai_addr);
                if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf))) {
                    [results addObject:[NSString stringWithUTF8String:buf]];
                }
            } else if (p->ai_family == AF_INET6) {
                auto *sin6 = reinterpret_cast<struct sockaddr_in6 *>(p->ai_addr);
                if (inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf))) {
                    [results addObject:[NSString stringWithUTF8String:buf]];
                }
            }
        }
        freeaddrinfo(res);
    }

    return results;
}

- (void)resolveAllNodeServerIPsWithCompletion:(void (^)(NSSet<NSString *> *))completion {
    NSArray<IPProxyNode *> *allNodes = self.nodes;
    NSMutableSet<NSString *> *uniqueHosts = [NSMutableSet set];
    for (IPProxyNode *node in allNodes) {
        if (node.server.length > 0) {
            [uniqueHosts addObject:node.server];
        }
    }

    if (uniqueHosts.count == 0) {
        if (completion) completion([NSSet set]);
        return;
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSMutableSet<NSString *> *resolvedIPs = [NSMutableSet set];
        NSLock *lock = [[NSLock alloc] init];
        dispatch_group_t group = dispatch_group_create();

        for (NSString *host in uniqueHosts) {
            dispatch_group_async(group, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                NSSet<NSString *> *ips = [SubscriptionManager resolveHostToIPAddresses:host];
                if (ips.count > 0) {
                    [lock lock];
                    [resolvedIPs unionSet:ips];
                    [lock unlock];
                }
            });
        }

        dispatch_group_notify(group, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            if (completion) {
                completion([resolvedIPs copy]);
            }
        });
    });
}

@end
