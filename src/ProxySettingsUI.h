#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface ProxySettingsUI : NSObject

+ (instancetype)sharedUI;

/// Installs a global 2-finger triple-tap gesture recognizer on the active key UIWindow
/// without touching any Instagram internal classes.
- (void)installGestureTrigger;

/// Programmatically presents the InstaProxy settings panel over the topmost view controller.
- (void)presentSettingsPanel;

@end

NS_ASSUME_NONNULL_END
