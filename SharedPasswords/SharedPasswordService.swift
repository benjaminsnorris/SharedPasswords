/*
 |  _   ____   ____   _
 | ⎛ |‾|  ⚈ |-| ⚈  |‾| ⎞
 | ⎝ |  ‾‾‾‾| |‾‾‾‾  | ⎠
 |  ‾        ‾        ‾
 */

import Foundation
import ReSwift

// MARK: - Actions

struct SharedPasswordError: Action {
    var error: ErrorType
}

struct SharedPasswordRetrieved: Action, CustomStringConvertible {
    var username: String
    var password: String
    
    var description: String {
        return "SharedPasswordRetrieved(email:\(username))"
    }
}


struct SharedPasswordService {
    
    // MARK: - Enums
    
    enum Error: ErrorType {
        case nilCredentials
        case malformedCredentials
        case missingCredentials
    }
    
    
    // MARK: - Internal functions
    
    func requestCredentials<T: StateType>(state: T, store: Store<T>) -> Action? {
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
