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


public struct SharedPasswordService {
    
    // MARK: - Enums
    
    public enum Error: ErrorType {
        case nilCredentials
        case malformedCredentials
        case missingCredentials
    }
    
    
    // MARK: - Initializers
    
    public init() { }
    
    
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

}
