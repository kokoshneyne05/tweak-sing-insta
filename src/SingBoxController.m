#import "SingBoxController.h"
#import "ProxyInterceptor.h"
#import "SubscriptionManager.h"

#import <Libbox/Libbox.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

NSString *const kInstaProxyStatusDidChangeNotification = @"InstaProxyStatusDidChangeNotification";
static NSString *const kSingBoxErrorDomain = @"com.instaproxy.singbox";

// MARK: - LibboxPlatformInterface Implementation (Jailed In-Process Mode)

@interface IPPlatformInterface : NSObject <LibboxPlatformInterface>
@end

@implementation IPPlatformInterface

- (BOOL)usePlatformAutoDetectInterfaceControl {
    return NO;
}

- (BOOL)autoDetectInterfaceControl:(int32_t)fd error:(NSError * _Nullable * _Nullable)error {
    return YES;
}

- (BOOL)openTun:(id _Nullable)options ret0_:(int32_t * _Nullable)ret0_ error:(NSError * _Nullable * _Nullable)error {
    if (error) {
        *error = [NSError errorWithDomain:kSingBoxErrorDomain
                                     code:3001
                                 userInfo:@{ NSLocalizedDescriptionKey : @"TUN mode is not supported in jailed dylib mode." }];
    }
    return NO;
}

- (BOOL)useProcFS {
    return NO;
}

- (BOOL)findConnectionOwner:(int32_t)ipProtocol
              sourceAddress:(NSString * _Nullable)sourceAddress
                 sourcePort:(int32_t)sourcePort
         destinationAddress:(NSString * _Nullable)destinationAddress
            destinationPort:(int32_t)destinationPort
                      ret0_:(int32_t * _Nullable)ret0_
                      error:(NSError * _Nullable * _Nullable)error {
    if (ret0_) *ret0_ = -1;
    return NO;
}

- (NSString * _Nonnull)packageNameByUid:(int32_t)uid error:(NSError * _Nullable * _Nullable)error {
    return @"";
}

- (BOOL)uidByPackageName:(NSString * _Nullable)packageName ret0_:(int32_t * _Nullable)ret0_ error:(NSError * _Nullable * _Nullable)error {
    if (ret0_) *ret0_ = -1;
    return NO;
}

- (void)writeLog:(NSString * _Nullable)message {
    if (message.length > 0) {
        NSLog(@"[InstaProxy/sing-box] %@", message);
    }
}

- (BOOL)startDefaultInterfaceMonitor:(id _Nullable)listener error:(NSError * _Nullable * _Nullable)error {
    return YES;
}

- (BOOL)closeDefaultInterfaceMonitor:(id _Nullable)listener error:(NSError * _Nullable * _Nullable)error {
    return YES;
}

- (id _Nullable)getInterfaces:(NSError * _Nullable * _Nullable)error {
    return nil;
}

- (BOOL)underNetworkExtension {
    return NO;
}

- (BOOL)includeAllNetworks {
    return NO;
}

- (void)clearDNSCache {
}

- (id _Nullable)readWIFIState {
    return nil;
}

- (id _Nullable)localDNSTransport {
    return nil;
}

- (id _Nullable)systemCertificates {
    return nil;
}

- (BOOL)sendNotification:(id _Nullable)notification error:(NSError * _Nullable * _Nullable)error {
    return YES;
}

@end

// MARK: - SingBoxController

@interface SingBoxController ()
@property (nonatomic, assign, readwrite) IPSingBoxState state;
@property (nonatomic, copy, readwrite, nullable) NSString *lastErrorMessage;
@property (nonatomic, copy, readwrite, nullable) NSString *activeServerName;
@property (nonatomic, assign, readwrite) NSInteger activeServerDelayMs;

@property (nonatomic, strong) dispatch_queue_t coreQueue;
@property (nonatomic, strong) IPPlatformInterface *platformInterface;
@property (nonatomic, strong, nullable) LibboxBoxService *boxService;
@property (nonatomic, assign) BOOL libboxInitialized;
@end

@implementation SingBoxController

+ (instancetype)sharedController {
    static SingBoxController *controller = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        controller = [[SingBoxController alloc] init];
    });
    return controller;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _coreQueue = dispatch_queue_create("com.instaproxy.singbox.core", DISPATCH_QUEUE_SERIAL);
        _platformInterface = [[IPPlatformInterface alloc] init];
        _state = IPSingBoxStateStopped;
        _activeServerDelayMs = -1;
    }
    return self;
}

- (NSString *)coreVersion {
    NSString *ver = LibboxVersion();
    return ver.length > 0 ? ver : @"sing-box";
}

// MARK: - Sandbox Directory Setup

- (BOOL)ensureLibboxSetupWithError:(NSError * _Nullable * _Nullable)error {
    if (self.libboxInitialized) {
        return YES;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    NSURL *appSupport = [fm URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask].firstObject;
    NSURL *cachesDir = [fm URLsForDirectory:NSCachesDirectory inDomains:NSUserDomainMask].firstObject;

    NSString *basePath = [appSupport.path stringByAppendingPathComponent:@"InstaProxy"];
    NSString *workingPath = [basePath stringByAppendingPathComponent:@"work"];
    NSString *tempPath = [cachesDir.path stringByAppendingPathComponent:@"InstaProxyTemp"];

    for (NSString *dir in @[ basePath, workingPath, tempPath ]) {
        NSError *dirErr = nil;
        if (![fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:&dirErr]) {
            if (error) *error = dirErr;
            return NO;
        }
    }

    LibboxSetupOptions *opts = [[LibboxSetupOptions alloc] init];
    opts.basePath = basePath;
    opts.workingPath = workingPath;
    opts.tempPath = tempPath;

    NSError *setupErr = nil;
    BOOL ok = LibboxSetup(opts, &setupErr);
    if (!ok && setupErr) {
        if (error) *error = setupErr;
        return NO;
    }

    self.libboxInitialized = YES;
    return YES;
}

// MARK: - Loopback Readiness Probe

- (BOOL)waitForLocalProxyPort:(uint16_t)port timeoutMs:(int)timeoutMs {
    int elapsed = 0;
    const int stepMs = 100;

    while (elapsed < timeoutMs) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0) {
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_len = sizeof(addr);
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

            if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) == 0) {
                close(fd);
                return YES;
            }
            close(fd);
        }
        usleep(stepMs * 1000);
        elapsed += stepMs;
    }
    return NO;
}

- (void)notifyStatusChange {
    dispatch_async(dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter] postNotificationName:kInstaProxyStatusDidChangeNotification object:self];
    });
}

// MARK: - Lifecycle

- (void)startIfEnabled {
    SubscriptionManager *subMgr = [SubscriptionManager sharedManager];
    if (!subMgr.proxyEnabled || subMgr.nodes.count == 0) {
        return;
    }
    [self startWithCompletion:nil];
}

- (void)startWithCompletion:(nullable void (^)(BOOL, NSError * _Nullable))completion {
    SubscriptionManager *subMgr = [SubscriptionManager sharedManager];

    if (subMgr.nodes.count == 0) {
        NSError *err = [NSError errorWithDomain:kSingBoxErrorDomain
                                           code:3002
                                       userInfo:@{ NSLocalizedDescriptionKey : @"Нет серверов для запуска. Добавьте подписку." }];
        self.state = IPSingBoxStateError;
        self.lastErrorMessage = err.localizedDescription;
        [self notifyStatusChange];
        if (completion) dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, err); });
        return;
    }

    // Resolve all upstream server IPs before starting sing-box so fishhook never loops them
    [subMgr resolveAllNodeServerIPsWithCompletion:^(NSSet<NSString *> *ipAddresses) {
        dispatch_async(self.coreQueue, ^{
            // Ensure interception is OFF while booting up
            ProxyInterceptor *interceptor = [ProxyInterceptor sharedInterceptor];
            interceptor.enabled = NO;
            interceptor.proxyPort = subMgr.localProxyPort;
            [interceptor setBypassIPAddresses:ipAddresses];

            // Close any existing instance
            if (self.boxService) {
                NSError *closeErr = nil;
                [self.boxService close:&closeErr];
                self.boxService = nil;
            }

            self.state = IPSingBoxStateStarting;
            self.lastErrorMessage = nil;
            [self notifyStatusChange];

            NSError *setupErr = nil;
            if (![self ensureLibboxSetupWithError:&setupErr]) {
                self.state = IPSingBoxStateError;
                self.lastErrorMessage = setupErr.localizedDescription ?: @"Ошибка инициализации Libbox.";
                [self notifyStatusChange];
                if (completion) dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, setupErr); });
                return;
            }

            NSError *cfgErr = nil;
            NSString *configJSON = [subMgr generateSingBoxConfigJSONWithError:&cfgErr];
            if (!configJSON || cfgErr) {
                self.state = IPSingBoxStateError;
                self.lastErrorMessage = cfgErr.localizedDescription ?: @"Ошибка генерации конфигурации sing-box.";
                [self notifyStatusChange];
                if (completion) dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, cfgErr); });
                return;
            }

            NSError *createErr = nil;
            LibboxBoxService *service = LibboxNewService(configJSON, self.platformInterface, &createErr);
            if (!service || createErr) {
                self.state = IPSingBoxStateError;
                self.lastErrorMessage = createErr.localizedDescription ?: @"Не удалось создать LibboxBoxService.";
                [self notifyStatusChange];
                if (completion) dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, createErr); });
                return;
            }

            NSError *startErr = nil;
            BOOL started = [service start:&startErr];
            if (!started || startErr) {
                [service close:nil];
                self.state = IPSingBoxStateError;
                self.lastErrorMessage = startErr.localizedDescription ?: @"Не удалось запустить ядро sing-box.";
                [self notifyStatusChange];
                if (completion) dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, startErr); });
                return;
            }

            self.boxService = service;

            // Wait until local mixed port 127.0.0.1:10808 is accepting TCP connections
            BOOL portReady = [self waitForLocalProxyPort:subMgr.localProxyPort timeoutMs:3000];
            if (!portReady) {
                NSError *timeoutErr = [NSError errorWithDomain:kSingBoxErrorDomain
                                                          code:3003
                                                      userInfo:@{ NSLocalizedDescriptionKey : @"Локальный порт 127.0.0.1:10808 не ответил вовремя." }];
                [self.boxService close:nil];
                self.boxService = nil;
                self.state = IPSingBoxStateError;
                self.lastErrorMessage = timeoutErr.localizedDescription;
                [self notifyStatusChange];
                if (completion) dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, timeoutErr); });
                return;
            }

            // Activate traffic interception now that local proxy is live
            interceptor.enabled = YES;
            self.state = IPSingBoxStateRunning;
            self.lastErrorMessage = nil;
            [self notifyStatusChange];

            // Fetch initial active server (urltest / selector) after brief delay
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.2 * NSEC_PER_SEC)), dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                [self refreshActiveServerWithCompletion:nil];
            });

            if (completion) {
                dispatch_async(dispatch_get_main_queue(), ^{ completion(YES, nil); });
            }
        });
    }];
}

- (void)stopWithCompletion:(nullable void (^)(void))completion {
    // Disable interception immediately before acquiring coreQueue so in-flight connections stop tunneling
    [ProxyInterceptor sharedInterceptor].enabled = NO;

    dispatch_async(self.coreQueue, ^{
        if (self.boxService) {
            self.state = IPSingBoxStateStopping;
            [self notifyStatusChange];

            NSError *closeErr = nil;
            [self.boxService close:&closeErr];
            self.boxService = nil;
        }

        self.state = IPSingBoxStateStopped;
        self.activeServerName = nil;
        self.activeServerDelayMs = -1;
        [self notifyStatusChange];

        if (completion) {
            dispatch_async(dispatch_get_main_queue(), ^{ completion(); });
        }
    });
}

- (void)restartWithCompletion:(nullable void (^)(BOOL, NSError * _Nullable))completion {
    [self stopWithCompletion:^{
        [self startWithCompletion:completion];
    }];
}

// MARK: - Live Clash API Control & Status

- (void)selectOutboundTag:(NSString *)tag
               completion:(nullable void (^)(BOOL, NSError * _Nullable))completion {
    SubscriptionManager *subMgr = [SubscriptionManager sharedManager];
    NSString *targetTag = (tag.length > 0) ? tag : kInstaProxyAutoOutboundTag;
    subMgr.selectedTag = targetTag;

    if (self.state != IPSingBoxStateRunning) {
        if (completion) dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, nil); });
        return;
    }

    NSString *urlStr = [NSString stringWithFormat:@"http://127.0.0.1:%u/proxies/%@",
                        subMgr.clashAPIPort,
                        kInstaProxySelectorOutboundTag];
    NSURL *url = [NSURL URLWithString:urlStr];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"PUT";
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = [NSJSONSerialization dataWithJSONObject:@{ @"name" : targetTag } options:0 error:nil];

    NSURLSessionConfiguration *cfg = [ProxyInterceptor directSessionConfiguration];
    cfg.timeoutIntervalForRequest = 3.0;
    NSURLSession *session = [NSURLSession sessionWithConfiguration:cfg];

    [[session dataTaskWithRequest:req completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        [session finishTasksAndInvalidate];
        BOOL ok = (!error && [response isKindOfClass:[NSHTTPURLResponse class]] && ((NSHTTPURLResponse *)response).statusCode < 300);
        if (ok) {
            [self refreshActiveServerWithCompletion:nil];
        }
        if (completion) {
            dispatch_async(dispatch_get_main_queue(), ^{ completion(ok, error); });
        }
    }] resume];
}

- (void)refreshActiveServerWithCompletion:(nullable void (^)(NSString * _Nullable, NSInteger))completion {
    if (self.state != IPSingBoxStateRunning) {
        if (completion) dispatch_async(dispatch_get_main_queue(), ^{ completion(nil, -1); });
        return;
    }

    SubscriptionManager *subMgr = [SubscriptionManager sharedManager];
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"http://127.0.0.1:%u/proxies", subMgr.clashAPIPort]];
    NSURLSessionConfiguration *cfg = [ProxyInterceptor directSessionConfiguration];
    cfg.timeoutIntervalForRequest = 3.0;
    NSURLSession *session = [NSURLSession sessionWithConfiguration:cfg];

    [[session dataTaskWithURL:url completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        [session finishTasksAndInvalidate];
        if (error || !data) {
            if (completion) dispatch_async(dispatch_get_main_queue(), ^{ completion(self.activeServerName, self.activeServerDelayMs); });
            return;
        }

        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        NSDictionary *proxies = [json isKindOfClass:[NSDictionary class]] ? json[@"proxies"] : nil;
        if (![proxies isKindOfClass:[NSDictionary class]]) {
            if (completion) dispatch_async(dispatch_get_main_queue(), ^{ completion(self.activeServerName, self.activeServerDelayMs); });
            return;
        }

        NSDictionary *selectorObj = proxies[kInstaProxySelectorOutboundTag];
        NSString *nowTag = [selectorObj isKindOfClass:[NSDictionary class]] ? selectorObj[@"now"] : nil;
        NSString *resolvedTag = nowTag;

        if ([nowTag isEqualToString:kInstaProxyAutoOutboundTag]) {
            NSDictionary *autoObj = proxies[kInstaProxyAutoOutboundTag];
            NSString *autoNow = [autoObj isKindOfClass:[NSDictionary class]] ? autoObj[@"now"] : nil;
            if (autoNow.length > 0) {
                resolvedTag = autoNow;
            }
        }

        NSInteger delayMs = -1;
        if (resolvedTag.length > 0 && [proxies[resolvedTag] isKindOfClass:[NSDictionary class]]) {
            NSArray *history = proxies[resolvedTag][@"history"];
            if ([history isKindOfClass:[NSArray class]] && history.count > 0) {
                NSDictionary *lastEntry = history.lastObject;
                if ([lastEntry isKindOfClass:[NSDictionary class]] && [lastEntry[@"delay"] isKindOfClass:[NSNumber class]]) {
                    delayMs = [lastEntry[@"delay"] integerValue];
                }
            }
        }

        NSString *display = resolvedTag;
        if ([nowTag isEqualToString:kInstaProxyAutoOutboundTag] && resolvedTag.length > 0 && ![resolvedTag isEqualToString:kInstaProxyAutoOutboundTag]) {
            display = [NSString stringWithFormat:@"Авто → %@", resolvedTag];
        } else if ([resolvedTag isEqualToString:kInstaProxyAutoOutboundTag]) {
            display = @"Авто (тестирование серверов...)";
        }

        self.activeServerName = display;
        self.activeServerDelayMs = delayMs;
        [self notifyStatusChange];

        if (completion) {
            dispatch_async(dispatch_get_main_queue(), ^{ completion(display, delayMs); });
        }
    }] resume];
}

@end
