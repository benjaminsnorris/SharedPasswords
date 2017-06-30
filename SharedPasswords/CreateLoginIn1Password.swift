/*
 |  _   ____   ____   _
 | | |‾|  ⚈ |-| ⚈  |‾| |
 | | |  ‾‾‾‾| |‾‾‾‾  | |
 |  ‾        ‾        ‾
 */

import Reactor
import OnePasswordExtension

public struct CreateLoginIn1Password<T: State>: Command {
    
    public var urlString: String
    public var appTitle: String
    public var username: String?
    public var password: String?
    public var viewController: UIViewController
    public var button: Any
    
    public init(urlString: String, appTitle: String, username: String?, password: String?, viewController: UIViewController, button: Any) {
        self.urlString = urlString
        self.appTitle = appTitle
        self.username = username
        self.password = password
        self.viewController = viewController
        self.button = button
    }
    
    public func execute(state: T, core: Core<T>) {
        let loginDetails: [String: Any] = [
            AppExtensionTitleKey: self.appTitle as Any,
            AppExtensionUsernameKey: self.username as Any,
            AppExtensionPasswordKey: self.password as Any
        ]
        
        OnePasswordExtension.shared().storeLogin(forURLString: urlString, loginDetails: loginDetails, passwordGenerationOptions: nil, for: viewController, sender: button) { loginDictionary, error in
            if let loginDictionary = loginDictionary , error == nil {
                guard let username = loginDictionary[AppExtensionUsernameKey] as? String, let password = loginDictionary[AppExtensionPasswordKey] as? String else {
                    core.fire(event: SharedPasswordErrorEvent(error: SharedPasswordError.missingCredentials))
                    return
                }
                let credential = Credential(server: self.urlString, accountName: username, password: password)
                do {
                    try credential.save(password)
                    core.fire(event: SharedPasswordCreated(credential: credential))
                } catch {
                    core.fire(event: SharedPasswordErrorEvent(error: error))
                }
            } else if let error = error as NSError?, error.code != Int(AppExtensionErrorCodeCancelledByUser) {
                core.fire(event: SharedPasswordErrorEvent(error: error))
            }
        }
    }
    
}
