/*
 |  _   ____   ____   _
 | | |‾|  ⚈ |-| ⚈  |‾| |
 | | |  ‾‾‾‾| |‾‾‾‾  | |
 |  ‾        ‾        ‾
 */

import Foundation

public struct Credential {
    
    // MARK: - Enums
    
    enum KeychainError: Error {
        case noPassword
        case unexpectedPasswordData
        case unexpectedItemData
        case unhandledError(status: OSStatus)
    }

    
    // MARK: - Public properties
    
    public var server: String?
    public var accountName: String

    
    // MARK: - Computed properties
    
    public var password: String? {
        if let privatePassword = privatePassword {
            return privatePassword
        }
        return try? readPassword()
    }
    
    
    // MARK: - Private properties
    
    fileprivate var privatePassword: String?
    
    
    // MARK: - Initializers
    
    public init(server: String?, accountName: String, password: String? = nil) {
        self.server = server
        self.accountName = accountName
        privatePassword = password
    }
    
    
    // MARK: - Public functions
    
    public static func allCredentials(for server: String?) throws -> [Credential] {
        var query = Credential.keychainQuery(with: server)
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        query[kSecReturnAttributes as String] = kCFBooleanTrue
        query[kSecReturnData as String] = kCFBooleanFalse
        
        var queryResult: AnyObject?
        let status = withUnsafeMutablePointer(to: &queryResult) {
            SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer($0))
        }
        guard status != errSecItemNotFound else { return [] }
        guard status == noErr else { throw KeychainError.unhandledError(status: status) }
        guard let resultData = queryResult as? [[String : AnyObject]] else { throw KeychainError.unexpectedItemData }
        
        var credentials = [Credential]()
        try resultData.forEach {
            guard let account = $0[kSecAttrAccount as String] as? String else { throw KeychainError.unexpectedItemData }
            let credential = Credential(server: server, accountName: account)
            credentials.append(credential)
        }

        return credentials
    }
    
    public func save(_ password: String) throws {
        let encodedPassword = password.data(using: String.Encoding.utf8)!
        do {
            try _ = readPassword()
            
            var update = [String: Any]()
            update[kSecValueData as String] = encodedPassword
            let query = Credential.keychainQuery(with: server, account: accountName)
            let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
            guard status == noErr else { throw KeychainError.unhandledError(status: status) }
        } catch KeychainError.noPassword {
            var newCredential = Credential.keychainQuery(with: server, account: accountName)
            newCredential[kSecValueData as String] = encodedPassword
            newCredential[kSecAttrSynchronizable as String] = kCFBooleanTrue
            let status = SecItemAdd(newCredential as CFDictionary, nil)
            guard status == noErr else { throw KeychainError.unhandledError(status: status) }
        }
    }
    
    public func delete() throws {
        let query = Credential.keychainQuery(with: server, account: accountName)
        let status = SecItemDelete(query as CFDictionary)
        guard status == noErr || status == errSecItemNotFound else { throw KeychainError.unhandledError(status: status) }
    }
    
}


// MARK: - Custom string convertible

extension Credential: CustomStringConvertible {
    
    public var description: String {
        return "Credential(server: \(String(describing: server)), accountName: \(accountName)"
    }
    
}


// MARK: - Private functions

private extension Credential {
    
    static func keychainQuery(with server: String?, account: String? = nil) -> [String: Any] {
        var query = [String: Any]()
        query[kSecClass as String] = kSecClassInternetPassword
        query[kSecAttrSynchronizable as String] = kSecAttrSynchronizableAny
        if let server = server {
            query[kSecAttrServer as String] = server
        }
        if let account = account {
            query[kSecAttrAccount as String] = account
        }
        return query
    }
    
    func readPassword() throws -> String {
        var query = Credential.keychainQuery(with: server, account: accountName)
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnAttributes as String] = kCFBooleanTrue
        query[kSecReturnData as String] = kCFBooleanTrue
        
        var queryResult: AnyObject?
        let status = withUnsafeMutablePointer(to: &queryResult) {
            SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer($0))
        }

        guard status != errSecItemNotFound else { throw KeychainError.noPassword }
        guard status == noErr else { throw KeychainError.unhandledError(status: status) }
        guard let existingItem = queryResult as? [String : Any],
            let passwordData = existingItem[kSecValueData as String] as? Data,
            let password = String(data: passwordData, encoding: String.Encoding.utf8)
            else {
                throw KeychainError.unexpectedPasswordData
        }
        
        return password
    }
    
}
