/*
 |  _   ____   ____   _
 | | |‾|  ⚈ |-| ⚈  |‾| |
 | | |  ‾‾‾‾| |‾‾‾‾  | |
 |  ‾        ‾        ‾
 */

import Reactor

public struct SaveSharedCredentialIfNeeded<T: State>: Command {
    
    public var urlString: String
    public var username: String
    public var password: String
    
    public init(urlString: String, username: String, password: String) {
        self.urlString = urlString
        self.username = username
        self.password = password
    }
    
    public func execute(state: T, core: Core<T>) {
        var savedCredentials = [String: [String: Any]]()
        var savedDomainCredentials = [String: Any]()
        if let credentials = UserDefaults.standard.object(forKey: Keys.sharedCredentials) as? [String: [String: Any]] {
            savedCredentials = credentials
            if let domainCredentials = savedCredentials[urlString] {
                savedDomainCredentials = domainCredentials
                if domainCredentials.keys.contains(username) {
                    return
                }
            }
        }
        SecAddSharedWebCredential(urlString as CFString, username as CFString, password as CFString?) { error in
            if let error = error {
                core.fire(event: SharedPasswordErrorEvent(error: error))
                print("status=failed-to-add-shared-credential error=\(error) domain=\(self.urlString) username=\(self.username)")
            } else {
                savedDomainCredentials[self.username] = true
                savedCredentials[self.urlString] = savedDomainCredentials
                UserDefaults.standard.set(savedCredentials, forKey: Keys.sharedCredentials)
                let credential = Credential(server: self.urlString, accountName: self.username)
                do {
                    try credential.save(self.password)
                    core.fire(event: SharedPasswordSaved(credential: credential))
                } catch {
                    core.fire(event: SharedPasswordErrorEvent(error: error))
                }
            }
        }
    }
    
}
