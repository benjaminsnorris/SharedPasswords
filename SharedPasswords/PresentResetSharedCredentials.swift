/*
 |  _   ____   ____   _
 | | |‾|  ⚈ |-| ⚈  |‾| |
 | | |  ‾‾‾‾| |‾‾‾‾  | |
 |  ‾        ‾        ‾
 */

import OnePasswordExtension
import Reactor

struct PresentResetSharedCredentials<T: State>: Command {
    
    var urlString: String
    var username: String?
    var viewController: UIViewController
    var sender: Any
    
    func execute(state: T, core: Core<T>) {
        var savedCredentials = [String: [String: Any]]()
        var savedDomainCredentials = [String: Any]()
        if let credentials = UserDefaults.standard.object(forKey: Keys.sharedCredentials) as? [String: [String: Any]] {
            savedCredentials = credentials
            if let domainCredentials = savedCredentials[urlString] {
                savedDomainCredentials = domainCredentials
            }
        }
        let alert = UIAlertController(title: NSLocalizedString("Reset shared credentials", comment: "Title for action sheet to reset shared credentials when logging in"), message: NSLocalizedString("This is typically not needed.\n\nBy default, the app will only save your shared credentials once, as subsequent attempts force you to confirm a password update whether it has changed or not.\n\nIf necessary, you can reset all shared credentials, or remove a specific saved password to force the credentials to save.", comment: "Explanation for action sheet to reset shared credentials"), preferredStyle: .actionSheet)
        if let username = username , username.characters.count > 0 {
            alert.addAction(UIAlertAction(title: NSLocalizedString("Remove saved password", comment: "Event title"), style: .destructive, handler: { _ in
                savedDomainCredentials.removeValue(forKey: username)
                savedCredentials[self.urlString] = savedDomainCredentials
                UserDefaults.standard.set(savedCredentials, forKey: Keys.sharedCredentials)
                core.fire(command: RemoveSharedCredentials(urlString: self.urlString, username: username))
            }))
        }
        alert.addAction(UIAlertAction(title: NSLocalizedString("Reset all credentials", comment: "Event title"), style: .destructive) { action in
            savedCredentials.removeValue(forKey: self.urlString)
            UserDefaults.standard.set(savedCredentials, forKey: Keys.sharedCredentials)
        })
        alert.addAction(UIAlertAction(title: NSLocalizedString("Cancel", comment: "Cancel button title"), style: .cancel, handler: nil))
        if let barButtonItem = sender as? UIBarButtonItem {
            alert.popoverPresentationController?.barButtonItem = barButtonItem
        } else if let view = sender as? UIView {
            alert.popoverPresentationController?.sourceView = view.superview
            alert.popoverPresentationController?.sourceRect = view.frame
        }
        viewController.present(alert, animated: true, completion: nil)
    }
    
}
