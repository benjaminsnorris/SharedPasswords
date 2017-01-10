/*
 |  _   ____   ____   _
 | | |‾|  ⚈ |-| ⚈  |‾| |
 | | |  ‾‾‾‾| |‾‾‾‾  | |
 |  ‾        ‾        ‾
 */

import OnePasswordExtension
import Reactor

public struct FindLoginFrom1Password<T: State>: Command {
    
    public var urlString: String
    public var viewController: UIViewController
    public var button: Any
    
    public init(urlString: String, viewController: UIViewController, button: Any) {
        self.urlString = urlString
        self.viewController = viewController
        self.button = button
    }
    
    public func execute(state: T, core: Core<T>) {
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
