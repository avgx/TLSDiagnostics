import Foundation
import Testing
import SSLPinning
@testable import TLSDiagnostics

@Suite("TLS Diagnostics Integration", .serialized)
struct TLSDiagnosticsTests {

    private func probe(
        _ url: String,
        policy: ServerTrustPolicy = .system
    ) async throws -> TLSProbe.Result {
        try await TLSProbe.inspect(
            for: URL(string: url)!,
            policy: policy
        )
    }
    
    @Test
    func exampleDotCom() async throws {
        let result = try await TLSProbe.inspect(
            for: URL(string: "https://www.example.com")!,
            policy: .system
        )

        #expect(result.chain.isEmpty == false)

        #expect(
            result.trustStatus?.isTrusted == true
        )

        #expect(
            result.pinningError == nil
        )

        #expect(
            result.chain.first?.commonName != nil
        )
    }

    @Test
    func sha256BadSSL() async throws {
        let result = try await TLSProbe.inspect(
            for: URL(string: "https://sha256.badssl.com")!,
            policy: .system
        )

        #expect(result.chain.isEmpty == false)

        #expect(
            result.trustStatus?.isTrusted == true
        )
    }

    @Test
    func selfSignedBadSSL() async throws {

        let result = try await probe(
            "https://self-signed.badssl.com/"
        )

        #expect(result.chain.count == 1)

        #expect(
            result.trustStatus?.isTrusted == false
        )

        #expect(
            result.chain.first?.isSelfSigned == true
        )
    }

    @Test
    func expiredBadSSL() async throws {

        let result = try await probe(
            "https://expired.badssl.com/"
        )

        #expect(result.chain.isEmpty == false)

        #expect(
            result.trustStatus?.isTrusted == false
        )

        #expect(
            result.trustStatus?.errorDescription != nil
        )
    }

    @Test
    func wrongHostBadSSL() async throws {
        let result = try await TLSProbe.inspect(
            for: URL(string: "https://wrong.host.badssl.com")!,
            policy: .system
        )

        #expect(result.chain.isEmpty == false)

        #expect(
            result.trustStatus?.isTrusted == false
        )
    }

    @Test
    func untrustedRootBadSSL() async throws {
        let result = try await TLSProbe.inspect(
            for: URL(string: "https://untrusted-root.badssl.com")!,
            policy: .system
        )

        #expect(result.chain.isEmpty == false)

        #expect(
            result.trustStatus?.isTrusted == false
        )
    }

    @Test
    func incompleteChainBadSSL() async throws {
        let result = try await TLSProbe.inspect(
            for: URL(string: "https://incomplete-chain.badssl.com")!,
            policy: .system
        )

        #expect(result.chain.isEmpty == false)
    }

    @Test
    func noCommonNameBadSSL() async throws {
        let result = try await TLSProbe.inspect(
            for: URL(string: "https://no-common-name.badssl.com")!,
            policy: .system
        )

        #expect(result.chain.isEmpty == false)

        let leaf = try #require(
            result.chain.first
        )

        #expect(
            leaf.commonName.isEmpty == true
        )
    }

    @Test
    func noSubjectBadSSL() async throws {
        let result = try await TLSProbe.inspect(
            for: URL(string: "https://no-subject.badssl.com")!,
            policy: .system
        )

        #expect(result.chain.isEmpty == false)
    }

    @Test
    func cloudflareByIP() async throws {

        let result = try await TLSProbe.inspect(
            for: URL(string: "https://1.1.1.1")!,
            policy: .trustEveryone,
            redirectPolicy: .suppress
        )
        
        let leaf = try #require(
            result.chain.first
        )

        #expect(
            leaf.validityRange.notBefore < Date()
        )

        #expect(
            leaf.validityRange.notAfter > Date()
        )
    }

    @Test
    func pinningSucceeds() async throws {
        let discovered = try await probe(
            "https://pinning-test.badssl.com/",
            policy: .trustEveryone
        )

        let leaf = try #require(
            discovered.chain.first
        )
        
        let pin = Fingerprint(
            host: "pinning-test.badssl.com",
            serialNumber: leaf.serialNumber,
            sha256: leaf.sha256,
            sha1: leaf.sha1
        )
        
        let pinned = try await probe(
            "https://pinning-test.badssl.com/",
            policy: .pinning([pin])
        )

        #expect(
            pinned.pinningError == nil
        )
    }
    
    @Test
    func wrongPinProducesPinMismatch() async throws {
        let result = try await TLSProbe.inspect(
            for: URL(string: "https://www.example.com")!,
            policy: .pinning([
                Fingerprint(
                    host: "www.example.com",
                    serialNumber: "00",
                    sha256: "00",
                    sha1: "00"
                )
            ])
        )

        guard case .fingerprintMismatch(_, _, _) = result.pinningError else {
            Issue.record("Expected fingerprintMismatch")
            return
        }
    }

    @Test
    func probeReturnsChainEvenWhenTrustFails() async throws {
        let result = try await TLSProbe.inspect(
            for: URL(string: "https://self-signed.badssl.com")!,
            policy: .system
        )

        #expect(result.chain.isEmpty == false)

        #expect(
            result.trustStatus?.isTrusted == false
        )
    }
}
