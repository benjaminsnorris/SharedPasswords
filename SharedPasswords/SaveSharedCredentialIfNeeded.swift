/*
 |  _   ____   ____   _
 | | |‾|  ⚈ |-| ⚈  |‾| |
 | | |  ‾‾‾‾| |‾‾‾‾  | |
 |  ‾        ‾        ‾
 */

import Reactor

struct SaveSharedCredentialIfNeeded<T: State>: Command {
    
    var urlString: String
    var username: String
    var password: String
    
    func execute(state: T, core: Core<T>) {
        var savedCredentials = [String: [String: Any]]()
        var savedDomainCredentials = [String: Any]()
        if let credentials = UserDefaults.standard.object(forKey: sharedCredentialsKey) as? [String: [String: Any]] {
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
                UserDefaults.standard.set(savedCredentials, forKey: sharedCredentialsKey)
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
