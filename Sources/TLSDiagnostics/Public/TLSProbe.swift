import Foundation
import SSLPinning

public enum TLSProbe {
    public struct Result: Sendable {
        public let chain: [CertificateInfo]
        public let trustStatus: SystemTrustStatus?
        public let pinningError: SSLPinningError?
    }
    
    public enum Error: LocalizedError {
        case notHTTPS
        case noCertificates(host: String)
    
        public var errorDescription: String? {
            switch self {
            case .notHTTPS:
                "Certificate preview is only available for https URLs."
            case .noCertificates(let host):
                "No server certificate chain was captured for \(host)."
            }
        }
    }

    
    public static func inspect(
        for url: URL,
        policy: ServerTrustPolicy,
        redirectPolicy: RedirectPolicy = .follow
    ) async throws -> Result {

        guard url.scheme?.lowercased() == "https" else {
            throw Error.notHTTPS
        }

        let (session, delegate) = ProbeNetworkSession.makeSession(policy: policy)

        defer {
            session.finishTasksAndInvalidate()
        }

        do {
            _ = try await session.data(from: url)
        } catch {
            // ignore
        }

        let host = url.host ?? ""
        let hostKey = host.lowercased()

        let chain = delegate.evaluator.certificateChainsByHost[host]
            ?? delegate.evaluator.certificateChainsByHost.first { $0.key.lowercased() == hostKey }?.value
        
        guard let chain, !chain.isEmpty else {
            throw Error.noCertificates(host: host)
        }

        return Result(
            chain: chain,
            trustStatus: delegate.evaluator.trustStatusByHost[host],
            pinningError: delegate.lastPinningError
        )
    }
}
