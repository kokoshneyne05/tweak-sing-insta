#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import "ProxyInterceptor.h"
#import "ProxySettingsUI.h"
#import "SingBoxController.h"
#import "SubscriptionManager.h"

static void InstaProxyHandleAppLaunch(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        [[ProxySettingsUI sharedUI] installGestureTrigger];
        [[SingBoxController sharedController] startIfEnabled];
    });
}

__attribute__((constructor))
static void InstaProxyConstructor(void) {
    @autoreleasepool {
        // 1. Install fishhook C-socket hooks & NSURLSessionConfiguration swizzling immediately.
        // Interception remains disabled (atomic false) until SingBoxController confirms 127.0.0.1:10808 is ready.
        ProxyInterceptor *interceptor = [ProxyInterceptor sharedInterceptor];
        interceptor.proxyPort = [SubscriptionManager sharedManager].localProxyPort;
        [interceptor installHooks];

        // 2. Register UIApplicationDidFinishLaunchingNotification for UI gesture attachment and core auto-start.
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                          object:nil
                                                           queue:[NSOperationQueue mainQueue]
                                                      usingBlock:^(NSNotification *note) {
            InstaProxyHandleAppLaunch();
        }];

        // 3. Fallback timer in case the dylib is injected or initialized after DidFinishLaunching has already fired.
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            InstaProxyHandleAppLaunch();
        });
    }
}
