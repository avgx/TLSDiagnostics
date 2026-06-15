import Foundation
import SSLPinning

enum ProbeNetworkSession {

    static func makeSession(
        policy: ServerTrustPolicy,
        redirectPolicy: RedirectPolicy = .follow
    ) -> (session: URLSession, delegate: PinningSessionDelegate) {
        let delegate = PinningSessionDelegate(
            policy: policy, 
        )
        delegate.suppressHttpRedirects = redirectPolicy == .suppress
        
        let configuration = URLSessionConfiguration.ephemeral

        configuration.timeoutIntervalForRequest = 5
        configuration.timeoutIntervalForResource = 5

        let session = URLSession(
            configuration: configuration,
            delegate: delegate,
            delegateQueue: nil
        )

        return (session, delegate)
    }
}
