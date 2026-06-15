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
        case handshakeFailed(underlyingError: Swift.Error)
        
        public var errorDescription: String? {
            switch self {
            case .notHTTPS:
                "Certificate preview is only available for https URLs."
            case .noCertificates(let host):
                "No server certificate chain was captured for \(host)."
            case .handshakeFailed(underlyingError: let underlyingError):
                "TLS handshake failed: \(underlyingError.localizedDescription)"
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

        let requestError: Swift.Error?
        do {
            _ = try await session.data(from: url)
            requestError = nil
        } catch {
            try? await Task.sleep(nanoseconds: 100_000_000) // 100ms
            
            if delegate.evaluator.certificateChainsByHost.keys.isEmpty {
                do {
                    _ = try await session.data(from: url)
                    requestError = nil
                } catch {
                    requestError = error
                }
            } else {
                requestError = nil
            }
        }
        
        let host = url.host ?? ""
        let hostKey = host.lowercased()
        
        let chain = delegate.evaluator.certificateChainsByHost[host]
            ?? delegate.evaluator.certificateChainsByHost.first { $0.key.lowercased() == hostKey }?.value
        
        guard let chain, !chain.isEmpty else {
            if let requestError {
                throw Error.handshakeFailed(
                    underlyingError: requestError
                )
            }
            throw Error.noCertificates(host: host)
        }

        return Result(
            chain: chain,
            trustStatus: delegate.evaluator.trustStatusByHost[host],
            pinningError: delegate.lastPinningError
        )
    }
}
