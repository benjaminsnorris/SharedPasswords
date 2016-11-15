/*
 |  _   ____   ____   _
 | | |‾|  ⚈ |-| ⚈  |‾| |
 | | |  ‾‾‾‾| |‾‾‾‾  | |
 |  ‾        ‾        ‾
 */

import Foundation
import ReSwift
import OnePasswordExtension

// MARK: - Actions

public struct SharedPasswordError: Action {
    public var error: Error
    
    public init(error: Error) {
        self.error = error
    }
}

public struct SharedPasswordRetrieved: Action {
    public var credential: Credential
    public init(credential: Credential) { self.credential = credential }
}

public struct SharedPasswordCreated: Action {
    public var credential: Credential
    public init(credential: Credential) { self.credential = credential }
}

public struct SharedPasswordSaved: Action {
    public var credential: Credential
    public init(credential: Credential) { self.credential = credential }
}

public struct SharedPasswordRemoved: Action {
    public var credential: Credential
    public init(credential: Credential) { self.credential = credential }
}


public struct SharedPasswordService {
    
    // MARK: - Enums
    
    public enum SharedPasswordServiceError: Error {
        case nilCredentials
        case malformedCredentials
        case missingCredentials
    }
    
    
    // MARK: - Initializers
    
    public init() { }
    
    
    // MARK: - Constants
    
    fileprivate static let sharedCredentialsKey = "sharedCredentials"
    
    
    // MARK: - Public functions
    
    public func requestCredentials<T: StateType>(for domain: String? = nil) -> (_ state: T, _ store: Store<T>) -> Action? {
        return { state, store in
            SecRequestSharedWebCredential(domain as CFString?, nil) { credentials, error in
                DispatchQueue.main.async {
                    guard error == nil else {
                        store.dispatch(SharedPasswordError(error: error!))
                        return
                    }
                    guard let unwrappedCredentials = credentials else {
                        store.dispatch(SharedPasswordError(error: SharedPasswordServiceError.nilCredentials))
                        return
                    }
                    let arrayCredentials = unwrappedCredentials as [AnyObject]
                    guard let typedCredentials = arrayCredentials as? [[String: Any]] else {
                        store.dispatch(SharedPasswordError(error: SharedPasswordServiceError.malformedCredentials))
                        return
                    }
                    guard let credentialDictionary = typedCredentials.first else {
                        store.dispatch(SharedPasswordError(error: SharedPasswordServiceError.missingCredentials))
                        return
                    }
                    guard let username = credentialDictionary[String(kSecAttrAccount)] as? String, let password = credentialDictionary[String(kSecSharedPassword)] as? String else {
                        store.dispatch(SharedPasswordError(error: SharedPasswordServiceError.missingCredentials))
                        return
                    }
                    let credential = Credential(server: domain, accountName: username, password: password)
                }
            }
            return nil
        }
    }
    
    public func saveSharedCredentialIfNeeded<T: StateType>(for urlString: String, username: String, password: String) -> (_ state: T, _ store: Store<T>) -> Action? {
        return { state, store in
            var savedCredentials = [String: [String: Any]]()
            var savedDomainCredentials = [String: Any]()
            if let credentials = UserDefaults.standard.object(forKey: SharedPasswordService.sharedCredentialsKey) as? [String: [String: Any]] {
                savedCredentials = credentials
                if let domainCredentials = savedCredentials[urlString] {
                    savedDomainCredentials = domainCredentials
                    if domainCredentials.keys.contains(username) {
                        return nil
                    }
                }
            }
            SecAddSharedWebCredential(urlString as CFString, username as CFString, password as CFString?) { error in
                if let error = error {
                    store.dispatch(SharedPasswordError(error: error))
                    print("status=failed-to-add-shared-credential error=\(error) domain=\(urlString) username=\(username)")
                } else {
                    savedDomainCredentials[username] = true
                    savedCredentials[urlString] = savedDomainCredentials
                    UserDefaults.standard.set(savedCredentials, forKey: SharedPasswordService.sharedCredentialsKey)
                    let credential = Credential(server: urlString, accountName: username)
                    do {
                        try credential.save(password)
                        store.dispatch(SharedPasswordSaved(credential: credential))
                    } catch {
                        store.dispatch(SharedPasswordError(error: error))
                    }
                }
            }
            return nil
        }
    }
    
    public func removeSharedCredentials<T: StateType>(for urlString: String, username: String) -> (_ state: T, _ store: Store<T>) -> Action? {
        return { state, store in
            var savedCredentials = [String: [String: Any]]()
            var savedDomainCredentials = [String: Any]()
            if let credentials = UserDefaults.standard.object(forKey: SharedPasswordService.sharedCredentialsKey) as? [String: [String: Any]] {
                savedCredentials = credentials
                if let domainCredentials = savedCredentials[urlString] {
                    savedDomainCredentials = domainCredentials
                }
            }

            SecAddSharedWebCredential(urlString as CFString, username as CFString, nil) { error in
                if let error = error {
                    store.dispatch(SharedPasswordError(error: error))
                    print("status=failed-to-add-shared-credential error=\(error) domain=\(urlString) username=\(username)")
                } else {
                    savedDomainCredentials.removeValue(forKey: username)
                    savedCredentials[urlString] = savedDomainCredentials
                    UserDefaults.standard.set(savedCredentials, forKey: SharedPasswordService.sharedCredentialsKey)
                    let credential = Credential(server: urlString, accountName: username)
                    do {
                        try credential.delete()
                        store.dispatch(SharedPasswordRemoved(credential: credential))
                    } catch {
                        store.dispatch(SharedPasswordError(error: error))
                    }
                }
            }
            return nil
        }
    }
    
    public func findLoginFrom1Password<T: StateType>(with urlString: String, viewController: UIViewController, button: Any) -> (_ state: T, _ store: Store<T>) -> Action? {
        return { state, store in
            OnePasswordExtension.shared().findLogin(forURLString: urlString, for: viewController, sender: button) { loginDictionary, error in
                guard error == nil else {
                    store.dispatch(SharedPasswordError(error: error!))
                    return
                }
                guard let loginDictionary = loginDictionary as? [String: Any] , loginDictionary.count > 0 else {
                    store.dispatch(SharedPasswordError(error: SharedPasswordServiceError.malformedCredentials))
                    return
                }
                guard let username = loginDictionary[AppExtensionUsernameKey] as? String, let password = loginDictionary[AppExtensionPasswordKey] as? String else {
                    store.dispatch(SharedPasswordError(error: SharedPasswordServiceError.missingCredentials))
                    return
                }
                let credential = Credential(server: urlString, accountName: username, password: password)
                store.dispatch(SharedPasswordRetrieved(credential: credential))
            }
            return nil
        }
    }
    
    public func createLoginIn1Password<T: StateType>(for urlString: String, appTitle: String, username: String? = nil, password: String? = nil, viewController: UIViewController, button: Any) -> (_ state: T, _ store: Store<T>) -> Action? {
        return { state, store in
            let username = username ?? ""
            let password = password ?? ""
            let loginDetails: [String: Any] = [
                AppExtensionTitleKey: appTitle as Any,
                AppExtensionUsernameKey: username as Any,
                AppExtensionPasswordKey: password as Any,
            ]
            OnePasswordExtension.shared().storeLogin(forURLString: urlString, loginDetails: loginDetails, passwordGenerationOptions: nil, for: viewController, sender: button) { loginDictionary, error in
                DispatchQueue.main.async {
                    if let loginDictionary = loginDictionary , error == nil {
                        guard let username = loginDictionary[AppExtensionUsernameKey] as? String, let password = loginDictionary[AppExtensionPasswordKey] as? String else {
                            store.dispatch(SharedPasswordError(error: SharedPasswordServiceError.missingCredentials))
                            return
                        }
                        let credential = Credential(server: urlString, accountName: username, password: password)
                        do {
                            try credential.save(password)
                            store.dispatch(SharedPasswordCreated(credential: credential))
                        } catch {
                            store.dispatch(SharedPasswordError(error: error))
                        }
                    } else if let error = error as? NSError, error.code != Int(AppExtensionErrorCodeCancelledByUser) {
                        store.dispatch(SharedPasswordError(error: error))
                    }
                }
            }
            return nil
        }
    }
    
    public func presentResetSharedCredentials<T: StateType>(for urlString: String, username: String?, viewController: UIViewController, sender: Any) -> (_ state: T, _ store: Store<T>) -> Action? {
        return { state, store in
            var savedCredentials = [String: [String: Any]]()
            var savedDomainCredentials = [String: Any]()
            if let credentials = UserDefaults.standard.object(forKey: SharedPasswordService.sharedCredentialsKey) as? [String: [String: Any]] {
                savedCredentials = credentials
                if let domainCredentials = savedCredentials[urlString] {
                    savedDomainCredentials = domainCredentials
                }
            }

            let alert = UIAlertController(title: NSLocalizedString("Reset shared credentials", comment: "Title for action sheet to reset shared credentials when logging in"), message: NSLocalizedString("This is typically not needed.\n\nBy default, the app will only save your shared credentials once, as subsequent attempts force you to confirm a password update whether it has changed or not.\n\nIf necessary, you can reset all shared credentials, or remove a specific saved password to force the credentials to save.", comment: "Explanation for action sheet to reset shared credentials"), preferredStyle: .actionSheet)
            if let username = username , username.characters.count > 0 {
                alert.addAction(UIAlertAction(title: NSLocalizedString("Remove saved password", comment: "Action title"), style: .destructive) { action in
                    savedDomainCredentials.removeValue(forKey: username)
                    savedCredentials[urlString] = savedDomainCredentials
                    UserDefaults.standard.set(savedCredentials, forKey: SharedPasswordService.sharedCredentialsKey)
                    store.dispatch(self.removeSharedCredentials(for: urlString, username: username))
                })
            }
            alert.addAction(UIAlertAction(title: NSLocalizedString("Reset all credentials", comment: "Action title"), style: .destructive) { action in
                savedCredentials.removeValue(forKey: urlString)
                UserDefaults.standard.set(savedCredentials, forKey: SharedPasswordService.sharedCredentialsKey)
            })
            alert.addAction(UIAlertAction(title: NSLocalizedString("Cancel", comment: "Cancel button title"), style: .cancel, handler: nil))
            if let barButtonItem = sender as? UIBarButtonItem {
                alert.popoverPresentationController?.barButtonItem = barButtonItem
            } else if let view = sender as? UIView {
                alert.popoverPresentationController?.sourceView = view.superview
                alert.popoverPresentationController?.sourceRect = view.frame
            }
            viewController.present(alert, animated: true, completion: nil)
            return nil
        }
    }

}
