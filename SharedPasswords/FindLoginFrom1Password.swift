/*
 |  _   ____   ____   _
 | | |‾|  ⚈ |-| ⚈  |‾| |
 | | |  ‾‾‾‾| |‾‾‾‾  | |
 |  ‾        ‾        ‾
 */

import OnePasswordExtension
import Reactor

struct FindLoginFrom1Password<T: State>: Command {
    
    var urlString: String
    var viewController: UIViewController
    var button: Any
    
    func execute(state: T, core: Core<T>) {
        OnePasswordExtension.shared().findLogin(forURLString: urlString, for: viewController, sender: button) { loginDictionary, error in
            guard error == nil else {
                core.fire(event: SharedPasswordErrorEvent(error: error!))
                return
            }
            guard let loginDictionary = loginDictionary as? [String: Any] , loginDictionary.count > 0 else {
                core.fire(event: SharedPasswordErrorEvent(error: SharedPasswordError.malformedCredentials))
                return
            }
            guard let username = loginDictionary[AppExtensionUsernameKey] as? String, let password = loginDictionary[AppExtensionPasswordKey] as? String else {
                core.fire(event: SharedPasswordErrorEvent(error: SharedPasswordError.missingCredentials))
                return
            }
            let credential = Credential(server: self.urlString, accountName: username, password: password)
            core.fire(event: SharedPasswordRetrieved(credential: credential))
        }
    }
    
}
