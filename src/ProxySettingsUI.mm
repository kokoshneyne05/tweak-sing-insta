#import "ProxySettingsUI.h"
#import "SingBoxController.h"
#import "SubscriptionManager.h"

#import <objc/runtime.h>

static const void *kInstaProxyGestureInstalledKey = &kInstaProxyGestureInstalledKey;

typedef NS_ENUM(NSInteger, IPSettingsSection) {
    IPSettingsSectionStatus = 0,
    IPSettingsSectionSubscriptions = 1,
    IPSettingsSectionServers = 2,
    IPSettingsSectionApply = 3,
    IPSettingsSectionCount = 4
};

// MARK: - ProxySettingsViewController

@interface ProxySettingsViewController : UITableViewController
@property (nonatomic, assign) BOOL pendingEnabled;
@property (nonatomic, copy) NSString *pendingSelectedTag;
@property (nonatomic, assign) BOOL isBusy;
@property (nonatomic, strong) NSDateFormatter *dateFormatter;
@end

@implementation ProxySettingsViewController

- (instancetype)init {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if (self) {
        _dateFormatter = [[NSDateFormatter alloc] init];
        _dateFormatter.dateStyle = NSDateFormatterShortStyle;
        _dateFormatter.timeStyle = NSDateFormatterShortStyle;
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];

    self.title = @"InstaProxy";
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithTitle:@"Закрыть"
                                                                              style:UIBarButtonItemStyleDone
                                                                             target:self
                                                                             action:@selector(closeTapped)];
    self.navigationItem.leftBarButtonItem = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh
                                                                                          target:self
                                                                                          action:@selector(refreshStatusTapped)];

    SubscriptionManager *subMgr = [SubscriptionManager sharedManager];
    self.pendingEnabled = subMgr.proxyEnabled;
    self.pendingSelectedTag = subMgr.selectedTag;

    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(handleStateChanged)
                                                 name:kInstaProxyStatusDidChangeNotification
                                               object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(handleStateChanged)
                                                 name:kInstaProxySubscriptionsDidChangeNotification
                                               object:nil];

    [[SingBoxController sharedController] refreshActiveServerWithCompletion:nil];
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)handleStateChanged {
    dispatch_async(dispatch_get_main_queue(), ^{
        [self.tableView reloadData];
    });
}

- (void)closeTapped {
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)refreshStatusTapped {
    [[SingBoxController sharedController] refreshActiveServerWithCompletion:^(NSString * _Nullable activeServer, NSInteger delayMs) {
        [self.tableView reloadSections:[NSIndexSet indexSetWithIndex:IPSettingsSectionStatus]
                      withRowAnimation:UITableViewRowAnimationNone];
    }];
}

- (void)showAlertWithTitle:(NSString *)title message:(NSString *)message {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                   message:message
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"ОК" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

// MARK: - Actions

- (void)proxySwitchChanged:(UISwitch *)sender {
    self.pendingEnabled = sender.isOn;
    [SubscriptionManager sharedManager].proxyEnabled = sender.isOn;

    if (!sender.isOn) {
        self.isBusy = YES;
        [self.tableView reloadData];
        [[SingBoxController sharedController] stopWithCompletion:^{
            self.isBusy = NO;
            [self.tableView reloadData];
        }];
    } else if ([SubscriptionManager sharedManager].nodes.count > 0) {
        self.isBusy = YES;
        [self.tableView reloadData];
        [[SingBoxController sharedController] startWithCompletion:^(BOOL success, NSError * _Nullable error) {
            self.isBusy = NO;
            if (!success && error) {
                [self showAlertWithTitle:@"Ошибка запуска ядра" message:error.localizedDescription];
            }
            [self.tableView reloadData];
        }];
    }
}

- (void)promptAddSubscription {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Добавить подписку"
                                                                   message:@"Вставьте URL подписки (Base64 VLESS/Trojan/SS/VMess или JSON sing-box)"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"https://example.com/sub/...";
        textField.keyboardType = UIKeyboardTypeURL;
        textField.autocapitalizationType = UITextAutocapitalizationTypeNone;
        textField.autocorrectionType = UITextAutocorrectionTypeNo;
        textField.clearButtonMode = UITextFieldViewModeWhileEditing;
    }];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"Название (необязательно)";
        textField.clearButtonMode = UITextFieldViewModeWhileEditing;
    }];

    [alert addAction:[UIAlertAction actionWithTitle:@"Отмена" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Добавить" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        NSString *urlText = alert.textFields[0].text ?: @"";
        NSString *nameText = alert.textFields[1].text ?: @"";
        if (urlText.length == 0) return;

        self.isBusy = YES;
        [self.tableView reloadData];

        [[SubscriptionManager sharedManager] addSubscriptionWithURL:urlText name:nameText completion:^(IPProxySubscription * _Nullable subscription, NSError * _Nullable error) {
            self.isBusy = NO;
            [self.tableView reloadData];
            if (error) {
                [self showAlertWithTitle:@"Ошибка загрузки" message:error.localizedDescription];
            } else {
                NSString *msg = [NSString stringWithFormat:@"Добавлено серверов: %ld", (long)subscription.nodeCount];
                [self showAlertWithTitle:@"Подписка загружена" message:msg];
            }
        }];
    }]];

    [self presentViewController:alert animated:YES completion:nil];
}

- (void)updateAllSubscriptions {
    if (self.isBusy) return;
    self.isBusy = YES;
    [self.tableView reloadData];

    [[SubscriptionManager sharedManager] updateAllSubscriptionsWithCompletion:^(NSInteger updatedCount, NSInteger failedCount, NSError * _Nullable lastError) {
        self.isBusy = NO;
        [self.tableView reloadData];
        if (failedCount > 0 && lastError) {
            NSString *msg = [NSString stringWithFormat:@"Обновлено: %ld, ошибок: %ld.\n%@",
                             (long)updatedCount, (long)failedCount, lastError.localizedDescription];
            [self showAlertWithTitle:@"Обновление завершено с ошибками" message:msg];
        } else if (updatedCount > 0) {
            NSString *msg = [NSString stringWithFormat:@"Успешно обновлено подписок: %ld. Нажмите «Применить и перезапустить ядро».",
                             (long)updatedCount];
            [self showAlertWithTitle:@"Подписки обновлены" message:msg];
        }
    }];
}

- (void)applyAndRestartCore {
    if (self.isBusy) return;

    SubscriptionManager *subMgr = [SubscriptionManager sharedManager];
    subMgr.proxyEnabled = self.pendingEnabled;
    subMgr.selectedTag = self.pendingSelectedTag;

    self.isBusy = YES;
    [self.tableView reloadData];

    SingBoxController *core = [SingBoxController sharedController];
    if (!self.pendingEnabled) {
        [core stopWithCompletion:^{
            self.isBusy = NO;
            [self.tableView reloadData];
        }];
        return;
    }

    [core restartWithCompletion:^(BOOL success, NSError * _Nullable error) {
        self.isBusy = NO;
        [self.tableView reloadData];
        if (!success && error) {
            [self showAlertWithTitle:@"Ошибка перезапуска" message:error.localizedDescription];
        }
    }];
}

// MARK: - UITableViewDataSource

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return IPSettingsSectionCount;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    switch (section) {
        case IPSettingsSectionStatus:
            return @"Статус и управление";
        case IPSettingsSectionSubscriptions:
            return @"Подписки (URL)";
        case IPSettingsSectionServers:
            return @"Выбор сервера";
        case IPSettingsSectionApply:
            return nil;
        default:
            return nil;
    }
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section == IPSettingsSectionStatus) {
        return [NSString stringWithFormat:@"Локальный прокси: 127.0.0.1:%u (HTTP/SOCKS5) · Ядро: %@\nЖест вызова меню: тройной тап двумя пальцами.",
                [SubscriptionManager sharedManager].localProxyPort,
                [SingBoxController sharedController].coreVersion];
    }
    if (section == IPSettingsSectionSubscriptions) {
        return @"Свайпните подписку влево для удаления.";
    }
    return nil;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    SubscriptionManager *subMgr = [SubscriptionManager sharedManager];
    switch (section) {
        case IPSettingsSectionStatus:
            return 3; // Switch, Status, Active Server
        case IPSettingsSectionSubscriptions:
            return subMgr.subscriptions.count + 2; // Saved subs + "Добавить URL" + "Обновить все"
        case IPSettingsSectionServers:
            return subMgr.nodes.count + 1; // "Автовыбор лучшего (urltest)" + nodes
        case IPSettingsSectionApply:
            return 1; // "Применить и перезапустить ядро"
        default:
            return 0;
    }
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    SubscriptionManager *subMgr = [SubscriptionManager sharedManager];
    SingBoxController *core = [SingBoxController sharedController];

    if (indexPath.section == IPSettingsSectionStatus) {
        if (indexPath.row == 0) {
            UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
            cell.selectionStyle = UITableViewCellSelectionStyleNone;
            cell.textLabel.text = @"Прокси активен";
            UISwitch *toggle = [[UISwitch alloc] init];
            toggle.on = self.pendingEnabled;
            toggle.enabled = !self.isBusy;
            [toggle addTarget:self action:@selector(proxySwitchChanged:) forControlEvents:UIControlEventValueChanged];
            cell.accessoryView = toggle;
            return cell;
        }
        if (indexPath.row == 1) {
            UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:nil];
            cell.selectionStyle = UITableViewCellSelectionStyleNone;
            cell.textLabel.text = @"Статус ядра";
            switch (core.state) {
                case IPSingBoxStateRunning:
                    cell.detailTextLabel.text = @"Работает";
                    cell.detailTextLabel.textColor = [UIColor systemGreenColor];
                    break;
                case IPSingBoxStateStarting:
                    cell.detailTextLabel.text = @"Запуск...";
                    cell.detailTextLabel.textColor = [UIColor systemOrangeColor];
                    break;
                case IPSingBoxStateStopping:
                    cell.detailTextLabel.text = @"Остановка...";
                    cell.detailTextLabel.textColor = [UIColor systemOrangeColor];
                    break;
                case IPSingBoxStateError:
                    cell.detailTextLabel.text = core.lastErrorMessage ?: @"Ошибка";
                    cell.detailTextLabel.textColor = [UIColor systemRedColor];
                    break;
                case IPSingBoxStateStopped:
                default:
                    cell.detailTextLabel.text = @"Остановлено";
                    cell.detailTextLabel.textColor = [UIColor secondaryLabelColor];
                    break;
            }
            return cell;
        }
        // Row 2: Active Server
        UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:nil];
        cell.textLabel.text = @"Активный сервер";
        if (core.state == IPSingBoxStateRunning) {
            NSString *serverText = core.activeServerName ?: (
                [subMgr.selectedTag isEqualToString:kInstaProxyAutoOutboundTag] ? @"Авто (urltest)" : subMgr.selectedTag
            );
            if (core.activeServerDelayMs > 0) {
                cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ (%ld мс)", serverText, (long)core.activeServerDelayMs];
            } else {
                cell.detailTextLabel.text = serverText;
            }
            cell.detailTextLabel.textColor = [UIColor labelColor];
        } else {
            cell.detailTextLabel.text = @"—";
            cell.detailTextLabel.textColor = [UIColor secondaryLabelColor];
        }
        return cell;
    }

    if (indexPath.section == IPSettingsSectionSubscriptions) {
        NSArray<IPProxySubscription *> *subs = subMgr.subscriptions;
        if (indexPath.row < (NSInteger)subs.count) {
            IPProxySubscription *sub = subs[indexPath.row];
            UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
            cell.selectionStyle = UITableViewCellSelectionStyleNone;
            cell.textLabel.text = sub.name;
            NSString *updatedStr = sub.lastUpdated ? [self.dateFormatter stringFromDate:sub.lastUpdated] : @"не обновлялась";
            if (sub.lastError.length > 0) {
                cell.detailTextLabel.text = [NSString stringWithFormat:@"Ошибка: %@", sub.lastError];
                cell.detailTextLabel.textColor = [UIColor systemRedColor];
            } else {
                cell.detailTextLabel.text = [NSString stringWithFormat:@"Серверов: %ld · Обновлено: %@\n%@",
                                             (long)sub.nodeCount, updatedStr, sub.url];
                cell.detailTextLabel.textColor = [UIColor secondaryLabelColor];
                cell.detailTextLabel.numberOfLines = 2;
            }
            return cell;
        }

        if (indexPath.row == (NSInteger)subs.count) {
            UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
            cell.textLabel.text = @"Добавить URL";
            cell.textLabel.textColor = [UIColor systemBlueColor];
            if (self.isBusy) {
                UIActivityIndicatorView *spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
                [spinner startAnimating];
                cell.accessoryView = spinner;
            }
            return cell;
        }

        UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
        cell.textLabel.text = @"Обновить все";
        cell.textLabel.textColor = subs.count > 0 ? [UIColor systemBlueColor] : [UIColor tertiaryLabelColor];
        cell.selectionStyle = subs.count > 0 ? UITableViewCellSelectionStyleDefault : UITableViewCellSelectionStyleNone;
        return cell;
    }

    if (indexPath.section == IPSettingsSectionServers) {
        if (indexPath.row == 0) {
            UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
            cell.textLabel.text = @"Автовыбор лучшего (urltest)";
            cell.textLabel.font = [UIFont systemFontOfSize:16 weight:UIFontWeightMedium];
            cell.detailTextLabel.text = @"Тест https://www.instagram.com/robots.txt каждые 5 мин";
            cell.detailTextLabel.textColor = [UIColor secondaryLabelColor];
            cell.accessoryType = [self.pendingSelectedTag isEqualToString:kInstaProxyAutoOutboundTag]
                ? UITableViewCellAccessoryCheckmark : UITableViewCellAccessoryNone;
            return cell;
        }

        IPProxyNode *node = subMgr.nodes[indexPath.row - 1];
        UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
        cell.textLabel.text = node.displayName;
        cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ · %@:%ld",
                                     node.protocol.uppercaseString, node.server, (long)node.port];
        cell.detailTextLabel.textColor = [UIColor secondaryLabelColor];
        cell.accessoryType = [self.pendingSelectedTag isEqualToString:node.tag]
            ? UITableViewCellAccessoryCheckmark : UITableViewCellAccessoryNone;
        return cell;
    }

    // Apply section
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
    cell.textLabel.text = self.isBusy ? @"Применение..." : @"Применить и перезапустить ядро";
    cell.textLabel.textAlignment = NSTextAlignmentCenter;
    cell.textLabel.font = [UIFont systemFontOfSize:16 weight:UIFontWeightSemibold];
    cell.textLabel.textColor = self.isBusy ? [UIColor secondaryLabelColor] : [UIColor systemBlueColor];
    return cell;
}

// MARK: - UITableViewDelegate & Swipe-to-Delete

- (BOOL)tableView:(UITableView *)tableView canEditRowAtIndexPath:(NSIndexPath *)indexPath {
    if (indexPath.section == IPSettingsSectionSubscriptions) {
        return indexPath.row < (NSInteger)[SubscriptionManager sharedManager].subscriptions.count;
    }
    return NO;
}

- (void)tableView:(UITableView *)tableView
commitEditingStyle:(UITableViewCellEditingStyle)editingStyle
forRowAtIndexPath:(NSIndexPath *)indexPath {
    if (editingStyle == UITableViewCellEditingStyleDelete && indexPath.section == IPSettingsSectionSubscriptions) {
        NSArray<IPProxySubscription *> *subs = [SubscriptionManager sharedManager].subscriptions;
        if (indexPath.row < (NSInteger)subs.count) {
            IPProxySubscription *sub = subs[indexPath.row];
            [[SubscriptionManager sharedManager] removeSubscriptionWithIdentifier:sub.identifier];
            self.pendingSelectedTag = [SubscriptionManager sharedManager].selectedTag;
        }
    }
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    SubscriptionManager *subMgr = [SubscriptionManager sharedManager];

    if (indexPath.section == IPSettingsSectionStatus && indexPath.row == 2) {
        [self refreshStatusTapped];
        return;
    }

    if (indexPath.section == IPSettingsSectionSubscriptions) {
        NSInteger subCount = subMgr.subscriptions.count;
        if (indexPath.row == subCount) {
            [self promptAddSubscription];
        } else if (indexPath.row == subCount + 1 && subCount > 0) {
            [self updateAllSubscriptions];
        }
        return;
    }

    if (indexPath.section == IPSettingsSectionServers) {
        NSString *chosenTag = (indexPath.row == 0)
            ? kInstaProxyAutoOutboundTag
            : subMgr.nodes[indexPath.row - 1].tag;

        self.pendingSelectedTag = chosenTag;
        [tableView reloadSections:[NSIndexSet indexSetWithIndex:IPSettingsSectionServers]
                 withRowAnimation:UITableViewRowAnimationNone];

        // Hot-switch immediately via Clash API if core is already running
        [[SingBoxController sharedController] selectOutboundTag:chosenTag completion:nil];
        return;
    }

    if (indexPath.section == IPSettingsSectionApply) {
        [self applyAndRestartCore];
    }
}

@end

// MARK: - ProxySettingsUI Manager & Gesture Trigger

@interface ProxySettingsUI () <UIGestureRecognizerDelegate>
@property (nonatomic, assign) BOOL gestureObserverRegistered;
@end

@implementation ProxySettingsUI

+ (instancetype)sharedUI {
    static ProxySettingsUI *ui = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        ui = [[ProxySettingsUI alloc] init];
    });
    return ui;
}

- (void)installGestureTrigger {
    if (self.gestureObserverRegistered) return;
    self.gestureObserverRegistered = YES;

    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
    [nc addObserver:self
           selector:@selector(attachGestureToActiveWindows)
               name:UIApplicationDidBecomeActiveNotification
             object:nil];
    [nc addObserver:self
           selector:@selector(attachGestureToActiveWindows)
               name:UIWindowDidBecomeKeyNotification
             object:nil];

    // Also schedule delayed attachments in case app is already active when constructor completes
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [self attachGestureToActiveWindows];
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [self attachGestureToActiveWindows];
    });
}

- (NSArray<UIWindow *> *)allApplicationWindows {
    NSMutableArray<UIWindow *> *windows = [NSMutableArray array];
    for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
        if ([scene isKindOfClass:[UIWindowScene class]]) {
            UIWindowScene *windowScene = (UIWindowScene *)scene;
            for (UIWindow *win in windowScene.windows) {
                if (!win.hidden && win.windowLevel == UIWindowLevelNormal) {
                    [windows addObject:win];
                }
            }
        }
    }
    return windows;
}

- (nullable UIWindow *)activeKeyWindow {
    NSArray<UIWindow *> *windows = [self allApplicationWindows];
    for (UIWindow *win in windows) {
        if (win.isKeyWindow) return win;
    }
    return windows.firstObject;
}

- (void)attachGestureToActiveWindows {
    dispatch_async(dispatch_get_main_queue(), ^{
        for (UIWindow *window in [self allApplicationWindows]) {
            if (objc_getAssociatedObject(window, kInstaProxyGestureInstalledKey) != nil) {
                continue;
            }
            UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(handleTripleTwoFingerTap:)];
            tap.numberOfTapsRequired = 3;
            tap.numberOfTouchesRequired = 2;
            tap.cancelsTouchesInView = NO;
            tap.delaysTouchesBegan = NO;
            tap.delaysTouchesEnded = NO;
            tap.delegate = self;
            [window addGestureRecognizer:tap];
            objc_setAssociatedObject(window, kInstaProxyGestureInstalledKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        }
    });
}

- (BOOL)gestureRecognizer:(UIGestureRecognizer *)gestureRecognizer
shouldRecognizeSimultaneouslyWithGestureRecognizer:(UIGestureRecognizer *)otherGestureRecognizer {
    return YES;
}

- (void)handleTripleTwoFingerTap:(UITapGestureRecognizer *)recognizer {
    if (recognizer.state == UIGestureRecognizerStateRecognized) {
        [self presentSettingsPanel];
    }
}

- (nullable UIViewController *)topMostViewControllerFrom:(UIViewController *)root {
    UIViewController *current = root;
    while (current.presentedViewController != nil) {
        current = current.presentedViewController;
    }
    return current;
}

- (void)presentSettingsPanel {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *keyWindow = [self activeKeyWindow];
        UIViewController *rootVC = keyWindow.rootViewController;
        if (!rootVC) return;

        UIViewController *topVC = [self topMostViewControllerFrom:rootVC];
        // Prevent presenting twice if already visible
        if ([topVC isKindOfClass:[UINavigationController class]]) {
            UINavigationController *nav = (UINavigationController *)topVC;
            if ([nav.topViewController isKindOfClass:[ProxySettingsViewController class]]) {
                return;
            }
        }

        ProxySettingsViewController *settingsVC = [[ProxySettingsViewController alloc] init];
        UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:settingsVC];
        nav.modalPresentationStyle = UIModalPresentationPageSheet;
        [topVC presentViewController:nav animated:YES completion:nil];
    });
}

@end
