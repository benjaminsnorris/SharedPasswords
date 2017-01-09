/*
 |  _   ____   ____   _
 | | |‾|  ⚈ |-| ⚈  |‾| |
 | | |  ‾‾‾‾| |‾‾‾‾  | |
 |  ‾        ‾        ‾
 */

import Reactor


// MARK: - Enums

public enum SharedPasswordError: Error {
    case nilCredentials
    case malformedCredentials
    case missingCredentials
}


// MARK: - Events

public struct SharedPasswordErrorEvent: Event {
    public var error: Error
    
    public init(error: Error) {
        self.error = error
    }
}

public struct SharedPasswordRetrieved: Event {
    public var credential: Credential
    public init(credential: Credential) { self.credential = credential }
}

public struct SharedPasswordCreated: Event {
    public var credential: Credential
    public init(credential: Credential) { self.credential = credential }
}

public struct SharedPasswordSaved: Event {
    public var credential: Credential
    public init(credential: Credential) { self.credential = credential }
}

public struct SharedPasswordRemoved: Event {
    public var credential: Credential
    public init(credential: Credential) { self.credential = credential }
}
