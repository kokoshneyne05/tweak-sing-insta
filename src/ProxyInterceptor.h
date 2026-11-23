#import <Foundation/Foundation.h>
#include <stdint.h>

NS_ASSUME_NONNULL_BEGIN

@interface ProxyInterceptor : NSObject

+ (instancetype)sharedInterceptor;

/// Installs fishhook C-socket rebindings and NSURLSessionConfiguration method swizzling.
/// Safe to call multiple times; hooks are installed once and remain inactive until enabled = YES.
- (void)installHooks;

/// Atomically enables or disables traffic redirection at runtime.
@property (nonatomic, assign, getter=isEnabled) BOOL enabled;

/// Local sing-box mixed (HTTP + SOCKS5) proxy port on 127.0.0.1. Default: 10808.
@property (nonatomic, assign) uint16_t proxyPort;

/// Replaces the set of upstream proxy server IP addresses (IPv4/IPv6 strings) that must
/// bypass interception so sing-box itself does not loop into its own local proxy.
- (void)setBypassIPAddresses:(NSSet<NSString *> *)ipAddresses;

/// Temporarily adds IP addresses (e.g., subscription host IPs) to the bypass set.
- (void)addTemporaryBypassIPAddresses:(NSSet<NSString *> *)ipAddresses;

/// Removes previously added temporary bypass IP addresses.
- (void)removeTemporaryBypassIPAddresses:(NSSet<NSString *> *)ipAddresses;

/// Executes a block on the current thread with NSURLSessionConfiguration proxy injection bypassed.
+ (void)performWithoutSessionProxy:(void (^)(void))block;

/// Creates an ephemeral NSURLSessionConfiguration guaranteed to bypass the local proxy.
+ (NSURLSessionConfiguration *)directSessionConfiguration;

@end

NS_ASSUME_NONNULL_END
