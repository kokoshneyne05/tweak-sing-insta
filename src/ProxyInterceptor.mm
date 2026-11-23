#import "ProxyInterceptor.h"

#import <CFNetwork/CFNetwork.h>
#import <objc/runtime.h>

#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <set>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_set>

#include "fishhook.h"

namespace {

// Thread-safe runtime state
std::atomic<bool> g_hooksInstalled{false};
std::atomic<bool> g_interceptionEnabled{false};
std::atomic<uint16_t> g_localProxyPort{10808};

// Re-entrancy guard for hooks invoked during SOCKS5 handshake on the same thread
thread_local bool g_inSocketHook = false;
// Thread-local bypass for internal NSURLSessionConfiguration requests (Clash API / subscription fetch)
thread_local int g_bypassSessionProxyDepth = 0;

// Mutex-protected bypass IP sets (network byte order for IPv4, raw 16 bytes for IPv6)
pthread_mutex_t g_bypassMutex = PTHREAD_MUTEX_INITIALIZER;
std::unordered_set<uint32_t> g_persistentBypassIPv4;
std::set<std::array<uint8_t, 16>> g_persistentBypassIPv6;
std::unordered_set<uint32_t> g_tempBypassIPv4;
std::set<std::array<uint8_t, 16>> g_tempBypassIPv6;

// Original C function pointers saved by fishhook
int (*orig_connect)(int, const struct sockaddr *, socklen_t) = nullptr;
ssize_t (*orig_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t) = nullptr;
ssize_t (*orig_sendmsg)(int, const struct msghdr *, int) = nullptr;

// Helper: check if an IPv4 address (network byte order) is loopback, private, link-local, or multicast
static bool isLocalOrPrivateIPv4(uint32_t addrNetOrder) {
    uint32_t ip = ntohl(addrNetOrder);
    uint8_t b0 = (ip >> 24) & 0xFF;
    uint8_t b1 = (ip >> 16) & 0xFF;

    // 0.0.0.0/8 (unspecified)
    if (b0 == 0) return true;
    // 127.0.0.0/8 (loopback)
    if (b0 == 127) return true;
    // 10.0.0.0/8 (RFC1918)
    if (b0 == 10) return true;
    // 172.16.0.0/12 (RFC1918)
    if (b0 == 172 && (b1 >= 16 && b1 <= 31)) return true;
    // 192.168.0.0/16 (RFC1918)
    if (b0 == 192 && b1 == 168) return true;
    // 169.254.0.0/16 (link-local)
    if (b0 == 169 && b1 == 254) return true;
    // 100.64.0.0/10 (CGNAT / carrier local)
    if (b0 == 100 && (b1 >= 64 && b1 <= 127)) return true;
    // 224.0.0.0/4 (multicast) & 240.0.0.0/4 (reserved/broadcast)
    if (b0 >= 224) return true;

    return false;
}

// Helper: check if IPv6 address is IPv4-mapped (::ffff:a.b.c.d)
static bool extractIPv4Mapped(const struct in6_addr &addr6, uint32_t *outIPv4NetOrder) {
    static const uint8_t kPrefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
    if (std::memcmp(addr6.s6_addr, kPrefix, 12) == 0) {
        if (outIPv4NetOrder) {
            std::memcpy(outIPv4NetOrder, addr6.s6_addr + 12, 4);
        }
        return true;
    }
    return false;
}

static bool isLocalOrPrivateIPv6(const struct in6_addr &addr6) {
    // :: (unspecified) or ::1 (loopback)
    if (IN6_IS_ADDR_UNSPECIFIED(&addr6) || IN6_IS_ADDR_LOOPBACK(&addr6)) {
        return true;
    }
    // Link-local fe80::/10
    if (IN6_IS_ADDR_LINKLOCAL(&addr6)) {
        return true;
    }
    // Multicast ff00::/8
    if (IN6_IS_ADDR_MULTICAST(&addr6)) {
        return true;
    }
    // Unique local fc00::/7 (fc00:: - fdff::)
    if ((addr6.s6_addr[0] & 0xFE) == 0xFC) {
        return true;
    }
    // IPv4-mapped IPv6
    uint32_t mapped4 = 0;
    if (extractIPv4Mapped(addr6, &mapped4)) {
        return isLocalOrPrivateIPv4(mapped4);
    }
    return false;
}

static bool isIPv4Bypassed(uint32_t addrNetOrder) {
    if (isLocalOrPrivateIPv4(addrNetOrder)) {
        return true;
    }
    // Public bootstrap DNS used by sing-box's direct DNS resolver
    uint32_t ipHost = ntohl(addrNetOrder);
    if (ipHost == 0x01010101u || ipHost == 0x01000001u ||
        ipHost == 0x08080808u || ipHost == 0x08080404u ||
        ipHost == 0x09090909u) {
        return true;
    }

    pthread_mutex_lock(&g_bypassMutex);
    bool found = (g_persistentBypassIPv4.find(addrNetOrder) != g_persistentBypassIPv4.end()) ||
                 (g_tempBypassIPv4.find(addrNetOrder) != g_tempBypassIPv4.end());
    pthread_mutex_unlock(&g_bypassMutex);
    return found;
}

static bool isIPv6Bypassed(const struct in6_addr &addr6) {
    if (isLocalOrPrivateIPv6(addr6)) {
        return true;
    }
    uint32_t mapped4 = 0;
    if (extractIPv4Mapped(addr6, &mapped4)) {
        return isIPv4Bypassed(mapped4);
    }

    // Public IPv6 bootstrap DNS (Cloudflare 2606:4700:4700::1111/1001, Google 2001:4860:4860::8888/8844)
    static const uint8_t kCFv6A[16] = {0x26,0x06,0x47,0x00,0x47,0x00,0,0,0,0,0,0,0,0,0x11,0x11};
    static const uint8_t kCFv6B[16] = {0x26,0x06,0x47,0x00,0x47,0x00,0,0,0,0,0,0,0,0,0x10,0x01};
    static const uint8_t kGGv6A[16] = {0x20,0x01,0x48,0x60,0x48,0x60,0,0,0,0,0,0,0,0,0x88,0x88};
    static const uint8_t kGGv6B[16] = {0x20,0x01,0x48,0x60,0x48,0x60,0,0,0,0,0,0,0,0,0x88,0x44};
    if (std::memcmp(addr6.s6_addr, kCFv6A, 16) == 0 ||
        std::memcmp(addr6.s6_addr, kCFv6B, 16) == 0 ||
        std::memcmp(addr6.s6_addr, kGGv6A, 16) == 0 ||
        std::memcmp(addr6.s6_addr, kGGv6B, 16) == 0) {
        return true;
    }

    std::array<uint8_t, 16> key{};
    std::memcpy(key.data(), addr6.s6_addr, 16);

    pthread_mutex_lock(&g_bypassMutex);
    bool found = (g_persistentBypassIPv6.find(key) != g_persistentBypassIPv6.end()) ||
                 (g_tempBypassIPv6.find(key) != g_tempBypassIPv6.end());
    pthread_mutex_unlock(&g_bypassMutex);
    return found;
}

static bool shouldBypassSockaddr(const struct sockaddr *addr, socklen_t addrlen) {
    if (!addr) return true;
    if (addr->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        const auto *sin = reinterpret_cast<const struct sockaddr_in *>(addr);
        return isIPv4Bypassed(sin->sin_addr.s_addr);
    }
    if (addr->sa_family == AF_INET6 && addrlen >= sizeof(struct sockaddr_in6)) {
        const auto *sin6 = reinterpret_cast<const struct sockaddr_in6 *>(addr);
        return isIPv6Bypassed(sin6->sin6_addr);
    }
    return true;
}

static uint16_t extractPortHostOrder(const struct sockaddr *addr, socklen_t addrlen) {
    if (!addr) return 0;
    if (addr->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        return ntohs(reinterpret_cast<const struct sockaddr_in *>(addr)->sin_port);
    }
    if (addr->sa_family == AF_INET6 && addrlen >= sizeof(struct sockaddr_in6)) {
        return ntohs(reinterpret_cast<const struct sockaddr_in6 *>(addr)->sin6_port);
    }
    return 0;
}

static int getSocketType(int sockfd) {
    int sockType = 0;
    socklen_t len = sizeof(sockType);
    if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &sockType, &len) != 0) {
        return -1;
    }
    return sockType;
}

// Wait for socket readiness using poll() (works cleanly for both blocking and O_NONBLOCK sockets)
static bool waitSocketEvent(int sockfd, short events, int timeoutMs) {
    struct pollfd pfd{};
    pfd.fd = sockfd;
    pfd.events = events;
    pfd.revents = 0;

    while (true) {
        int rc = poll(&pfd, 1, timeoutMs);
        if (rc > 0) {
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                return false;
            }
            if (pfd.revents & events) {
                return true;
            }
            return false;
        }
        if (rc == 0) {
            errno = ETIMEDOUT;
            return false;
        }
        if (errno == EINTR) {
            continue;
        }
        return false;
    }
}

static bool sendAllWithPoll(int sockfd, const uint8_t *buf, size_t len, int timeoutMs) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(sockfd, buf + sent, len - sent, 0);
        if (n > 0) {
            sent += static_cast<size_t>(n);
            continue;
        }
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (!waitSocketEvent(sockfd, POLLOUT, timeoutMs)) {
                    return false;
                }
                continue;
            }
        }
        return false;
    }
    return true;
}

static bool recvAllWithPoll(int sockfd, uint8_t *buf, size_t len, int timeoutMs) {
    size_t received = 0;
    while (received < len) {
        ssize_t n = recv(sockfd, buf + received, len - received, 0);
        if (n > 0) {
            received += static_cast<size_t>(n);
            continue;
        }
        if (n == 0) {
            errno = ECONNRESET;
            return false;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (!waitSocketEvent(sockfd, POLLIN, timeoutMs)) {
                return false;
            }
            continue;
        }
        return false;
    }
    return true;
}

// Performs RFC 1928 SOCKS5 CONNECT handshake over an already-connected socket to 127.0.0.1:proxyPort
static bool performSOCKS5Handshake(int sockfd, const struct sockaddr *targetAddr, socklen_t targetLen) {
    constexpr int kHandshakeTimeoutMs = 8000;

    // 1. Greeting: VER=5, NMETHODS=1, METHOD=0 (No Auth)
    const uint8_t greeting[3] = {0x05, 0x01, 0x00};
    if (!sendAllWithPoll(sockfd, greeting, sizeof(greeting), kHandshakeTimeoutMs)) {
        return false;
    }

    uint8_t methodReply[2] = {0};
    if (!recvAllWithPoll(sockfd, methodReply, sizeof(methodReply), kHandshakeTimeoutMs)) {
        return false;
    }
    if (methodReply[0] != 0x05 || methodReply[1] != 0x00) {
        errno = ECONNREFUSED;
        return false;
    }

    // 2. Build CONNECT request (VER=5, CMD=1, RSV=0, ATYP=1|4, DST.ADDR, DST.PORT)
    uint8_t req[22] = {0};
    size_t reqLen = 0;
    req[0] = 0x05;
    req[1] = 0x01; // CONNECT
    req[2] = 0x00;

    if (targetAddr->sa_family == AF_INET && targetLen >= sizeof(struct sockaddr_in)) {
        const auto *sin = reinterpret_cast<const struct sockaddr_in *>(targetAddr);
        req[3] = 0x01; // IPv4
        std::memcpy(req + 4, &sin->sin_addr.s_addr, 4);
        std::memcpy(req + 8, &sin->sin_port, 2);
        reqLen = 10;
    } else if (targetAddr->sa_family == AF_INET6 && targetLen >= sizeof(struct sockaddr_in6)) {
        const auto *sin6 = reinterpret_cast<const struct sockaddr_in6 *>(targetAddr);
        uint32_t mapped4 = 0;
        if (extractIPv4Mapped(sin6->sin6_addr, &mapped4)) {
            req[3] = 0x01; // IPv4-mapped -> send as IPv4 for maximal proxy compatibility
            std::memcpy(req + 4, &mapped4, 4);
            std::memcpy(req + 8, &sin6->sin6_port, 2);
            reqLen = 10;
        } else {
            req[3] = 0x04; // IPv6
            std::memcpy(req + 4, sin6->sin6_addr.s6_addr, 16);
            std::memcpy(req + 20, &sin6->sin6_port, 2);
            reqLen = 22;
        }
    } else {
        errno = EAFNOSUPPORT;
        return false;
    }

    if (!sendAllWithPoll(sockfd, req, reqLen, kHandshakeTimeoutMs)) {
        return false;
    }

    // 3. Read reply header: [VER, REP, RSV, ATYP]
    uint8_t respHeader[4] = {0};
    if (!recvAllWithPoll(sockfd, respHeader, sizeof(respHeader), kHandshakeTimeoutMs)) {
        return false;
    }
    if (respHeader[0] != 0x05 || respHeader[1] != 0x00) {
        errno = (respHeader[1] == 0x04 || respHeader[1] == 0x03) ? EHOSTUNREACH : ECONNREFUSED;
        return false;
    }

    // 4. Drain BND.ADDR + BND.PORT
    uint8_t drainBuf[260] = {0};
    size_t drainLen = 0;
    switch (respHeader[3]) {
        case 0x01: // IPv4 + port
            drainLen = 4 + 2;
            break;
        case 0x04: // IPv6 + port
            drainLen = 16 + 2;
            break;
        case 0x03: { // Domain: 1-byte length + domain + 2-byte port
            uint8_t domainLen = 0;
            if (!recvAllWithPoll(sockfd, &domainLen, 1, kHandshakeTimeoutMs)) {
                return false;
            }
            drainLen = static_cast<size_t>(domainLen) + 2;
            break;
        }
        default:
            errno = EPROTO;
            return false;
    }

    if (!recvAllWithPoll(sockfd, drainBuf, drainLen, kHandshakeTimeoutMs)) {
        return false;
    }
    return true;
}

// Connect socket to 127.0.0.1:proxyPort (handling both AF_INET and AF_INET6 sockets!)
static bool connectToLocalProxy(int sockfd, int socketFamily, uint16_t proxyPort) {
    int rc = -1;
    if (socketFamily == AF_INET) {
        struct sockaddr_in proxyAddr{};
        proxyAddr.sin_len = sizeof(proxyAddr);
        proxyAddr.sin_family = AF_INET;
        proxyAddr.sin_port = htons(proxyPort);
        proxyAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        rc = orig_connect(sockfd, reinterpret_cast<const struct sockaddr *>(&proxyAddr), sizeof(proxyAddr));
    } else if (socketFamily == AF_INET6) {
        // Connect natively to sing-box's IPv6 loopback listener [::1]:proxyPort first
        struct sockaddr_in6 proxyAddr6{};
        proxyAddr6.sin6_len = sizeof(proxyAddr6);
        proxyAddr6.sin6_family = AF_INET6;
        proxyAddr6.sin6_port = htons(proxyPort);
        proxyAddr6.sin6_addr = in6addr_loopback;

        rc = orig_connect(sockfd, reinterpret_cast<const struct sockaddr *>(&proxyAddr6), sizeof(proxyAddr6));
        if (rc != 0 && errno != EINPROGRESS) {
            // Fallback to IPv4-mapped loopback ::ffff:127.0.0.1 if IPv6 loopback is unavailable
            int off = 0;
            setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
            static const uint8_t kMappedLoopback[16] = {
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 127, 0, 0, 1
            };
            std::memcpy(proxyAddr6.sin6_addr.s6_addr, kMappedLoopback, 16);
            rc = orig_connect(sockfd, reinterpret_cast<const struct sockaddr *>(&proxyAddr6), sizeof(proxyAddr6));
        }
    } else {
        errno = EAFNOSUPPORT;
        return false;
    }

    if (rc == 0) {
        return true;
    }

    if (errno == EINPROGRESS) {
        if (!waitSocketEvent(sockfd, POLLOUT, 5000)) {
            return false;
        }
        int soErr = 0;
        socklen_t errLen = sizeof(soErr);
        if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &soErr, &errLen) != 0 || soErr != 0) {
            errno = soErr ? soErr : ECONNREFUSED;
            return false;
        }
        return true;
    }

    return false;
}

static int hooked_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!orig_connect) {
        errno = ENOSYS;
        return -1;
    }

    if (g_inSocketHook || !g_interceptionEnabled.load(std::memory_order_acquire) || !addr) {
        return orig_connect(sockfd, addr, addrlen);
    }

    if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6) {
        return orig_connect(sockfd, addr, addrlen);
    }

    if (shouldBypassSockaddr(addr, addrlen)) {
        return orig_connect(sockfd, addr, addrlen);
    }

    int sockType = getSocketType(sockfd);

    // Block UDP/443 (QUIC / HTTP3) so Meta Proxygen falls back cleanly to TCP/TLS
    if (sockType == SOCK_DGRAM) {
        if (extractPortHostOrder(addr, addrlen) == 443) {
            errno = EHOSTUNREACH;
            return -1;
        }
        return orig_connect(sockfd, addr, addrlen);
    }

    if (sockType != SOCK_STREAM) {
        return orig_connect(sockfd, addr, addrlen);
    }

    // Re-entrancy guard during local SOCKS5 tunnel establishment
    struct HookGuard {
        HookGuard() { g_inSocketHook = true; }
        ~HookGuard() { g_inSocketHook = false; }
    } guard;

    // Prevent SIGPIPE crashes on iOS if local sing-box closes during restart
    int noSigPipe = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, sizeof(noSigPipe));

    uint16_t proxyPort = g_localProxyPort.load(std::memory_order_relaxed);
    if (!connectToLocalProxy(sockfd, addr->sa_family, proxyPort)) {
        return -1;
    }

    if (!performSOCKS5Handshake(sockfd, addr, addrlen)) {
        int savedErrno = errno;
        errno = savedErrno ? savedErrno : ECONNREFUSED;
        return -1;
    }

    // Returning 0 immediately is POSIX-valid even for O_NONBLOCK sockets
    return 0;
}

static ssize_t hooked_sendto(int sockfd, const void *buf, size_t len, int flags,
                             const struct sockaddr *dest_addr, socklen_t addrlen) {
    if (!orig_sendto) {
        errno = ENOSYS;
        return -1;
    }

    if (!g_inSocketHook &&
        g_interceptionEnabled.load(std::memory_order_acquire) &&
        dest_addr != nullptr &&
        (dest_addr->sa_family == AF_INET || dest_addr->sa_family == AF_INET6)) {
        if (extractPortHostOrder(dest_addr, addrlen) == 443 &&
            getSocketType(sockfd) == SOCK_DGRAM &&
            !shouldBypassSockaddr(dest_addr, addrlen)) {
            errno = EHOSTUNREACH;
            return -1;
        }
    }

    return orig_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

static ssize_t hooked_sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    if (!orig_sendmsg) {
        errno = ENOSYS;
        return -1;
    }

    if (!g_inSocketHook &&
        g_interceptionEnabled.load(std::memory_order_acquire) &&
        msg != nullptr &&
        msg->msg_name != nullptr &&
        msg->msg_namelen > 0) {
        const auto *destAddr = reinterpret_cast<const struct sockaddr *>(msg->msg_name);
        if ((destAddr->sa_family == AF_INET || destAddr->sa_family == AF_INET6) &&
            extractPortHostOrder(destAddr, msg->msg_namelen) == 443 &&
            getSocketType(sockfd) == SOCK_DGRAM &&
            !shouldBypassSockaddr(destAddr, msg->msg_namelen)) {
            errno = EHOSTUNREACH;
            return -1;
        }
    }

    return orig_sendmsg(sockfd, msg, flags);
}

static NSDictionary *buildConnectionProxyDictionary(uint16_t port) {
    NSNumber *portNum = @(port);
    return @{
        (NSString *)kCFNetworkProxiesHTTPEnable : @YES,
        (NSString *)kCFNetworkProxiesHTTPProxy : @"127.0.0.1",
        (NSString *)kCFNetworkProxiesHTTPPort : portNum,
        @"HTTPSEnable" : @YES,
        @"HTTPSProxy" : @"127.0.0.1",
        @"HTTPSPort" : portNum,
        @"SOCKSEnable" : @YES,
        @"SOCKSProxy" : @"127.0.0.1",
        @"SOCKSPort" : portNum,
        @"ExceptionsList" : @[ @"127.0.0.1", @"localhost", @"::1", @"*.local" ]
    };
}

static void parseIPStringsIntoSets(NSSet<NSString *> *ipStrings,
                                   std::unordered_set<uint32_t> &outV4,
                                   std::set<std::array<uint8_t, 16>> &outV6) {
    for (NSString *ipStr in ipStrings) {
        if (![ipStr isKindOfClass:[NSString class]] || ipStr.length == 0) {
            continue;
        }
        const char *cstr = ipStr.UTF8String;
        if (!cstr) continue;

        struct in_addr addr4{};
        if (inet_pton(AF_INET, cstr, &addr4) == 1) {
            outV4.insert(addr4.s_addr);
            continue;
        }
        struct in6_addr addr6{};
        if (inet_pton(AF_INET6, cstr, &addr6) == 1) {
            std::array<uint8_t, 16> key{};
            std::memcpy(key.data(), addr6.s6_addr, 16);
            outV6.insert(key);
        }
    }
}

} // namespace

// MARK: - NSURLSessionConfiguration Swizzling Category

@interface NSURLSessionConfiguration (InstaProxySwizzle)
+ (NSURLSessionConfiguration *)ip_swizzledDefaultSessionConfiguration;
+ (NSURLSessionConfiguration *)ip_swizzledEphemeralSessionConfiguration;
@end

@implementation NSURLSessionConfiguration (InstaProxySwizzle)

+ (NSURLSessionConfiguration *)ip_swizzledDefaultSessionConfiguration {
    NSURLSessionConfiguration *config = [self ip_swizzledDefaultSessionConfiguration];
    if (g_bypassSessionProxyDepth == 0 && g_interceptionEnabled.load(std::memory_order_acquire)) {
        config.connectionProxyDictionary = buildConnectionProxyDictionary(
            g_localProxyPort.load(std::memory_order_relaxed));
    }
    return config;
}

+ (NSURLSessionConfiguration *)ip_swizzledEphemeralSessionConfiguration {
    NSURLSessionConfiguration *config = [self ip_swizzledEphemeralSessionConfiguration];
    if (g_bypassSessionProxyDepth == 0 && g_interceptionEnabled.load(std::memory_order_acquire)) {
        config.connectionProxyDictionary = buildConnectionProxyDictionary(
            g_localProxyPort.load(std::memory_order_relaxed));
    }
    return config;
}

@end

// MARK: - ProxyInterceptor Implementation

@implementation ProxyInterceptor

+ (instancetype)sharedInterceptor {
    static ProxyInterceptor *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[ProxyInterceptor alloc] init];
    });
    return instance;
}

- (void)installHooks {
    bool expected = false;
    if (!g_hooksInstalled.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return;
    }

    // 1. Swizzle NSURLSessionConfiguration class methods (no CydiaSubstrate required)
    Class configClass = [NSURLSessionConfiguration class];
    Method origDefault = class_getClassMethod(configClass, @selector(defaultSessionConfiguration));
    Method swizzledDefault = class_getClassMethod(configClass, @selector(ip_swizzledDefaultSessionConfiguration));
    if (origDefault && swizzledDefault) {
        method_exchangeImplementations(origDefault, swizzledDefault);
    }

    Method origEphemeral = class_getClassMethod(configClass, @selector(ephemeralSessionConfiguration));
    Method swizzledEphemeral = class_getClassMethod(configClass, @selector(ip_swizzledEphemeralSessionConfiguration));
    if (origEphemeral && swizzledEphemeral) {
        method_exchangeImplementations(origEphemeral, swizzledEphemeral);
    }

    // 2. Rebind POSIX BSD socket functions across all loaded Mach-O images via facebook/fishhook
    struct rebinding rebindings[3] = {
        {"connect", reinterpret_cast<void *>(hooked_connect), reinterpret_cast<void **>(&orig_connect)},
        {"sendto", reinterpret_cast<void *>(hooked_sendto), reinterpret_cast<void **>(&orig_sendto)},
        {"sendmsg", reinterpret_cast<void *>(hooked_sendmsg), reinterpret_cast<void **>(&orig_sendmsg)},
    };
    rebind_symbols(rebindings, 3);
}

- (BOOL)isEnabled {
    return g_interceptionEnabled.load(std::memory_order_acquire) ? YES : NO;
}

- (void)setEnabled:(BOOL)enabled {
    g_interceptionEnabled.store(enabled ? true : false, std::memory_order_release);
}

- (uint16_t)proxyPort {
    return g_localProxyPort.load(std::memory_order_relaxed);
}

- (void)setProxyPort:(uint16_t)proxyPort {
    if (proxyPort > 0) {
        g_localProxyPort.store(proxyPort, std::memory_order_relaxed);
    }
}

- (void)setBypassIPAddresses:(NSSet<NSString *> *)ipAddresses {
    std::unordered_set<uint32_t> newV4;
    std::set<std::array<uint8_t, 16>> newV6;
    parseIPStringsIntoSets(ipAddresses, newV4, newV6);

    pthread_mutex_lock(&g_bypassMutex);
    g_persistentBypassIPv4.swap(newV4);
    g_persistentBypassIPv6.swap(newV6);
    pthread_mutex_unlock(&g_bypassMutex);
}

- (void)addTemporaryBypassIPAddresses:(NSSet<NSString *> *)ipAddresses {
    std::unordered_set<uint32_t> addV4;
    std::set<std::array<uint8_t, 16>> addV6;
    parseIPStringsIntoSets(ipAddresses, addV4, addV6);

    pthread_mutex_lock(&g_bypassMutex);
    g_tempBypassIPv4.insert(addV4.begin(), addV4.end());
    g_tempBypassIPv6.insert(addV6.begin(), addV6.end());
    pthread_mutex_unlock(&g_bypassMutex);
}

- (void)removeTemporaryBypassIPAddresses:(NSSet<NSString *> *)ipAddresses {
    std::unordered_set<uint32_t> remV4;
    std::set<std::array<uint8_t, 16>> remV6;
    parseIPStringsIntoSets(ipAddresses, remV4, remV6);

    pthread_mutex_lock(&g_bypassMutex);
    for (uint32_t ip : remV4) {
        g_tempBypassIPv4.erase(ip);
    }
    for (const auto &ip6 : remV6) {
        g_tempBypassIPv6.erase(ip6);
    }
    pthread_mutex_unlock(&g_bypassMutex);
}

+ (void)performWithoutSessionProxy:(void (^)(void))block {
    if (!block) return;
    g_bypassSessionProxyDepth++;
    @try {
        block();
    } @finally {
        g_bypassSessionProxyDepth--;
    }
}

+ (NSURLSessionConfiguration *)directSessionConfiguration {
    __block NSURLSessionConfiguration *cfg = nil;
    [self performWithoutSessionProxy:^{
        cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        cfg.connectionProxyDictionary = @{};
    }];
    return cfg;
}

@end
