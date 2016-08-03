/*
 |  _   ____   ____   _
 | ⎛ |‾|  ⚈ |-| ⚈  |‾| ⎞
 | ⎝ |  ‾‾‾‾| |‾‾‾‾  | ⎠
 |  ‾        ‾        ‾
 */

import Foundation
import ReSwift
import Marshal

struct SharedPasswordService {
    
    // MARK: - Enums
    
    enum Error: ErrorType {
        case nilCredentials
        case malformedCredentials
        case missingCredentials
    }
    
    
    // MARK: - Internal properties
    
    var store = AppState.sharedStore
    
    
    // MARK: - Internal functions
    
    func requestCredentials(state: AppState, store: Store<AppState>) -> Action? {
        SecRequestSharedWebCredential(nil, nil) { credentials, error in
            dispatch_async(dispatch_get_main_queue()) {
                guard error == nil else {
                    self.store.dispatch(SharedPasswordError(error: error!))
                    return
                }
                guard let unwrappedCredentials = credentials else {
                    self.store.dispatch(SharedPasswordError(error: Error.nilCredentials))
                    return
                }
                let arrayCredentials = unwrappedCredentials as [AnyObject]
                guard let typedCredentials = arrayCredentials as? [[String: AnyObject]] else {
                    self.store.dispatch(SharedPasswordError(error: Error.malformedCredentials))
                    return
                }
                guard let credential = typedCredentials.first else {
                    self.store.dispatch(SharedPasswordError(error: Error.missingCredentials))
                    return
                }
                do {
                    let username: String = try credential <| String(kSecAttrAccount)
                    let password: String = try credential <| String(kSecSharedPassword)
                    self.store.dispatch(SharedPasswordRetrieved(username: username, password: password))
                } catch {
                    self.store.dispatch(SharedPasswordError(error: Error.missingCredentials))
                }
            }
        }
        return nil
    }

}
