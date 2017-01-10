/*
 |  _   ____   ____   _
 | | |‾|  ⚈ |-| ⚈  |‾| |
 | | |  ‾‾‾‾| |‾‾‾‾  | |
 |  ‾        ‾        ‾
 */

import Reactor

struct RemoveSharedCredentials<T: State>: Command {
    
    var urlString: String
    var username: String
    
    func execute(state: T, core: Core<T>) {
        var savedCredentials = [String: [String: Any]]()
        var savedDomainCredentials = [String: Any]()
        
        if let credentials = UserDefaults.standard.object(forKey: Keys.sharedCredentials) as? [String: [String: Any]] {
            savedCredentials = credentials
            if let domainCredentials = savedCredentials[urlString] {
                savedDomainCredentials = domainCredentials
            }
        }
        
        SecAddSharedWebCredential(urlString as CFString, username as CFString, nil) { error in
            if let error = error {
                core.fire(event: SharedPasswordErrorEvent(error: error))
                print("status=failed-to-add-shared-credential error=\(error) domain=\(self.urlString) username=\(self.username)")
            } else {
                savedDomainCredentials.removeValue(forKey: self.username)
                savedCredentials[self.urlString] = savedDomainCredentials
                UserDefaults.standard.set(savedCredentials, forKey: Keys.sharedCredentials)
                let credential = Credential(server: self.urlString, accountName: self.username)
                do {
                    try credential.delete()
                    core.fire(event: SharedPasswordRemoved(credential: credential))
                } catch {
                    core.fire(event: SharedPasswordErrorEvent(error: error))
                }
            }
        }
    }
    
}
