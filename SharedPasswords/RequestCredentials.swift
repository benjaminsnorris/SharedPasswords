/*
 |  _   ____   ____   _
 | | |‾|  ⚈ |-| ⚈  |‾| |
 | | |  ‾‾‾‾| |‾‾‾‾  | |
 |  ‾        ‾        ‾
 */

import Reactor

public struct RequestCredentials<T: State>: Command {
    
    public var domain: String?
    
    public init(domain: String?) {
        self.domain = domain
    }
    
    public func execute(state: T, core: Core<T>) {
        SecRequestSharedWebCredential(self.domain as CFString?, nil) { credentials, error in
            guard error == nil else {
                core.fire(event: SharedPasswordErrorEvent(error: error!))
                return
            }
            guard let unwrappedCredentials = credentials else {
                core.fire(event: SharedPasswordErrorEvent(error: SharedPasswordError.nilCredentials))
                return
            }
            let arrayCredentials = unwrappedCredentials as [AnyObject]
            guard let typedCredentials = arrayCredentials as? [[String: Any]] else {
                core.fire(event: SharedPasswordErrorEvent(error: SharedPasswordError.malformedCredentials))
                return
            }
            guard let credentialDictionary = typedCredentials.first else {
                core.fire(event: SharedPasswordErrorEvent(error: SharedPasswordError.missingCredentials))
                return
            }
            guard let username = credentialDictionary[String(kSecAttrAccount)] as? String, let password = credentialDictionary[String(kSecSharedPassword)] as? String else {
                core.fire(event: SharedPasswordErrorEvent(error: SharedPasswordError.missingCredentials))
                return
            }
            let credential = Credential(server: self.domain, accountName: username, password: password)
            core.fire(event: SharedPasswordRetrieved(credential: credential))
        }
    }
    
}
