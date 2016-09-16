/*
 |  _   ____   ____   _
 | ⎛ |‾|  ⚈ |-| ⚈  |‾| ⎞
 | ⎝ |  ‾‾‾‾| |‾‾‾‾  | ⎠
 |  ‾        ‾        ‾
 */

import Foundation
import ReSwift
import OnePasswordExtension

// MARK: - Actions

public struct SharedPasswordError: Action {
    public var error: ErrorType
    
    public init(error: ErrorType) {
        self.error = error
    }
}

public struct SharedPasswordRetrieved: Action, CustomStringConvertible {
    public var username: String
    public var password: String
    
    public init(username: String, password: String) {
        self.username = username
        self.password = password
    }
    
    public var description: String {
        return "SharedPasswordRetrieved(email:\(username))"
    }
}

public struct SharedPasswordCreated: Action, CustomStringConvertible {
    public var username: String
    public var password: String
    
    public init(username: String, password: String) {
        self.username = username
        self.password = password
    }
    
    public var description: String {
        return "SharedPasswordRetrieved(email:\(username))"
    }
}

public struct SharedPasswordSaved: Action {
    public var domain: String
    public var username: String
    public init(username: String, domain: String) {
        self.username = username
        self.domain = domain
    }
}

public struct SharedPasswordRemoved: Action {
    public var domain: String
    public var username: String
    public init(username: String, domain: String) {
        self.username = username
        self.domain = domain
    }
}


public struct SharedPasswordService {
    
    // MARK: - Enums
    
    public enum Error: ErrorType {
        case nilCredentials
        case malformedCredentials
        case missingCredentials
    }
    
    
    // MARK: - Initializers
    
    public init() { }
    
    
    // MARK: - Constants
    
    private static let sharedCredentialsKey = "sharedCredentials"
    
    
    // MARK: - Public functions
    
    public func requestCredentials<T: StateType>(for domain: String? = nil) -> (state: T, store: Store<T>) -> Action? {
        return { state, store in
            SecRequestSharedWebCredential(domain, nil) { credentials, error in
                dispatch_async(dispatch_get_main_queue()) {
                    guard error == nil else {
                        store.dispatch(SharedPasswordError(error: error!))
                        return
                    }
                    guard let unwrappedCredentials = credentials else {
                        store.dispatch(SharedPasswordError(error: Error.nilCredentials))
                        return
                    }
                    let arrayCredentials = unwrappedCredentials as [AnyObject]
                    guard let typedCredentials = arrayCredentials as? [[String: AnyObject]] else {
                        store.dispatch(SharedPasswordError(error: Error.malformedCredentials))
                        return
                    }
                    guard let credential = typedCredentials.first else {
                        store.dispatch(SharedPasswordError(error: Error.missingCredentials))
                        return
                    }
                    guard let username = credential[String(kSecAttrAccount)] as? String, password = credential[String(kSecSharedPassword)] as? String else {
                        store.dispatch(SharedPasswordError(error: Error.missingCredentials))
                        return
                    }
                    store.dispatch(SharedPasswordRetrieved(username: username, password: password))
                    guard let domain = domain else { return }
                }
            }
            return nil
        }
    }
    
    public func saveSharedCredentialIfNeeded<T: StateType>(for urlString: String, username: String, password: String) -> (state: T, store: Store<T>) -> Action? {
        return { state, store in
            var savedCredentials = [String: [String: AnyObject]]()
            var savedDomainCredentials = [String: AnyObject]()
            if let credentials = NSUserDefaults.standardUserDefaults().objectForKey(SharedPasswordService.sharedCredentialsKey) as? [String: [String: AnyObject]] {
                savedCredentials = credentials
                if let domainCredentials = savedCredentials[urlString] {
                    savedDomainCredentials = domainCredentials
                    if domainCredentials.keys.contains(username) {
                        return nil
                    }
                }
            }
            SecAddSharedWebCredential(urlString, username, password) { error in
                if let error = error {
                    store.dispatch(SharedPasswordError(error: error))
                    print("status=failed-to-add-shared-credential error=\(error) domain=\(urlString) username=\(username)")
                } else {
                    savedDomainCredentials[username] = true
                    savedCredentials[urlString] = savedDomainCredentials
                    NSUserDefaults.standardUserDefaults().setObject(savedCredentials, forKey: SharedPasswordService.sharedCredentialsKey)
                    store.dispatch(SharedPasswordSaved(username: username, domain: urlString))
                }
            }
            return nil
        }
    }
    
    public func removeSharedCredentials<T: StateType>(for urlString: String, username: String) -> (state: T, store: Store<T>) -> Action? {
        return { state, store in
            var savedCredentials = [String: [String: AnyObject]]()
            var savedDomainCredentials = [String: AnyObject]()
            if let credentials = NSUserDefaults.standardUserDefaults().objectForKey(SharedPasswordService.sharedCredentialsKey) as? [String: [String: AnyObject]] {
                savedCredentials = credentials
                if let domainCredentials = savedCredentials[urlString] {
                    savedDomainCredentials = domainCredentials
                }
            }

            SecAddSharedWebCredential(urlString, username, nil) { error in
                if let error = error {
                    store.dispatch(SharedPasswordError(error: error))
                    print("status=failed-to-add-shared-credential error=\(error) domain=\(urlString) username=\(username)")
                } else {
                    savedDomainCredentials.removeValueForKey(username)
                    savedCredentials[urlString] = savedDomainCredentials
                    NSUserDefaults.standardUserDefaults().setObject(savedCredentials, forKey: SharedPasswordService.sharedCredentialsKey)
                    store.dispatch(SharedPasswordSaved(username: username, domain: urlString))
                }
            }
            return nil
        }
    }
    
    public func findLoginFrom1Password<T: StateType>(with urlString: String, viewController: UIViewController, button: AnyObject) -> (state: T, store: Store<T>) -> Action? {
        return { state, store in
            OnePasswordExtension.sharedExtension().findLoginForURLString(urlString, forViewController: viewController, sender: button) { loginDictionary, error in
                guard error == nil else {
                    store.dispatch(SharedPasswordError(error: error!))
                    return
                }
                guard let loginDictionary = loginDictionary as? [String: AnyObject] where loginDictionary.count > 0 else {
                    store.dispatch(SharedPasswordError(error: Error.malformedCredentials))
                    return
                }
                guard let username = loginDictionary[AppExtensionUsernameKey] as? String, password = loginDictionary[AppExtensionPasswordKey] as? String else {
                    store.dispatch(SharedPasswordError(error: Error.missingCredentials))
                    return
                }
                store.dispatch(SharedPasswordRetrieved(username: username, password: password))
            }
            return nil
        }
    }
    
    public func createLoginIn1Password<T: StateType>(for urlString: String, appTitle: String, username: String? = nil, password: String? = nil, viewController: UIViewController, button: AnyObject) -> (state: T, store: Store<T>) -> Action? {
        return { state, store in
            let username = username ?? ""
            let password = password ?? ""
            let loginDetails: [String: AnyObject] = [
                AppExtensionTitleKey: appTitle,
                AppExtensionUsernameKey: username,
                AppExtensionPasswordKey: password,
            ]
            OnePasswordExtension.sharedExtension().storeLoginForURLString(urlString, loginDetails: loginDetails, passwordGenerationOptions: nil, forViewController: viewController, sender: button) { loginDictionary, error in
                dispatch_async(dispatch_get_main_queue()) {
                    if let loginDictionary = loginDictionary where error == nil {
                        guard let username = loginDictionary[AppExtensionUsernameKey] as? String, password = loginDictionary[AppExtensionPasswordKey] as? String else {
                            store.dispatch(SharedPasswordError(error: Error.missingCredentials))
                            return
                        }
                        store.dispatch(SharedPasswordCreated(username: username, password: password))
                    } else if let error = error where error.code != Int(AppExtensionErrorCodeCancelledByUser) {
                        store.dispatch(SharedPasswordError(error: error))
                    }
                }
            }
            return nil
        }
    }
    
    public func presentResetSharedCredentials<T: StateType>(for urlString: String, username: String?, viewController: UIViewController, sender: AnyObject) -> (state: T, store: Store<T>) -> Action? {
        return { state, store in
            var savedCredentials = [String: [String: AnyObject]]()
            var savedDomainCredentials = [String: AnyObject]()
            if let credentials = NSUserDefaults.standardUserDefaults().objectForKey(SharedPasswordService.sharedCredentialsKey) as? [String: [String: AnyObject]] {
                savedCredentials = credentials
                if let domainCredentials = savedCredentials[urlString] {
                    savedDomainCredentials = domainCredentials
                }
            }

            let alert = UIAlertController(title: NSLocalizedString("Reset shared credentials", comment: "Title for action sheet to reset shared credentials when logging in"), message: NSLocalizedString("This is typically not needed.\n\nBy default, the app will only save your shared credentials once, as subsequent attempts force you to confirm a password update whether it has changed or not.\n\nIf necessary, you can reset all shared credentials, or reset a specific username to force the credentials to save.", comment: "Explanation for action sheet to reset shared credentials"), preferredStyle: .ActionSheet)
            if let username = username where username.characters.count > 0 {
                alert.addAction(UIAlertAction(title: NSLocalizedString("Force password update", comment: "Action title"), style: .Default) { action in
                    savedDomainCredentials.removeValueForKey(username)
                    savedCredentials[urlString] = savedDomainCredentials
                    NSUserDefaults.standardUserDefaults().setObject(savedCredentials, forKey: SharedPasswordService.sharedCredentialsKey)
                    store.dispatch(self.removeSharedCredentials(for: urlString, username: username))
                })
            }
            alert.addAction(UIAlertAction(title: NSLocalizedString("Reset all credentials", comment: "Action title"), style: .Destructive) { action in
                savedCredentials.removeValueForKey(urlString)
                NSUserDefaults.standardUserDefaults().setObject(savedCredentials, forKey: SharedPasswordService.sharedCredentialsKey)
            })
            alert.addAction(UIAlertAction(title: NSLocalizedString("Cancel", comment: "Cancel button title"), style: .Cancel, handler: nil))
            if let barButtonItem = sender as? UIBarButtonItem {
                alert.popoverPresentationController?.barButtonItem = barButtonItem
            } else if let view = sender as? UIView {
                alert.popoverPresentationController?.sourceView = view.superview
                alert.popoverPresentationController?.sourceRect = view.frame
            }
            viewController.presentViewController(alert, animated: true, completion: nil)
            return nil
        }
    }

}
