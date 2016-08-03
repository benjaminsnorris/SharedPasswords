/*
 |  _   ____   ____   _
 | ⎛ |‾|  ⚈ |-| ⚈  |‾| ⎞
 | ⎝ |  ‾‾‾‾| |‾‾‾‾  | ⎠
 |  ‾        ‾        ‾
 */

import Foundation
import ReSwift

// MARK: - Actions

public struct SharedPasswordError: Action {
    public var error: ErrorType
}

public struct SharedPasswordRetrieved: Action, CustomStringConvertible {
    public var username: String
    public var password: String
    
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
    
    
    // MARK: - Internal functions
    
    public func requestCredentials<T: StateType>(state: T, store: Store<T>) -> Action? {
        SecRequestSharedWebCredential(nil, nil) { credentials, error in
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
