/**
 * MITM CA loader/generator for the in-process TLS-terminating proxy.
 *
 * The CA is supplied via `network.tlsTerminate.{caCertPath,caKeyPath}` (see
 * sandbox-config.ts). If both paths are omitted, SRT generates an ephemeral
 * RSA-2048 self-signed CA into a temp directory; the cert path is what the
 * trust env vars point at. The caller is responsible for cleaning up via
 * `disposeMitmCA()` (SandboxManager.reset() does this).
 */
import forge from 'node-forge';
import type { SecureContext } from 'node:tls';
import type { LeafCert } from './mitm-leaf.js';
export type MitmCA = {
    certPath: string;
    keyPath: string;
    certPem: string;
    keyPem: string;
    /** Parsed CA certificate (issuer for minted leaf certs). */
    cert: forge.pki.Certificate;
    /** Parsed CA private key. RSA only. */
    key: forge.pki.rsa.PrivateKey;
    /** Per-hostname cache of leaf certs minted against this CA. */
    leafCerts: Map<string, LeafCert>;
    /** Per-hostname cache of TLS SecureContexts wrapping the leaf certs. */
    secureContexts: Map<string, SecureContext>;
    /**
     * True when SRT generated this CA into a temp directory. disposeMitmCA()
     * removes that directory; user-supplied CAs are left alone.
     */
    ephemeral: boolean;
};
/**
 * Create a MitmCA. If `caCertPath`/`caKeyPath` are provided, load from disk
 * (throws if either file is missing, unreadable, not PEM, fails to parse, or
 * the key is not RSA). If both are omitted, generate an ephemeral CA into a
 * fresh temp directory.
 *
 * Pure factory: no module-level state. The caller (SandboxManager) owns the
 * returned object and its lifetime.
 */
export declare function createMitmCA(opts: {
    caCertPath?: string;
    caKeyPath?: string;
}): MitmCA;
/** Remove the temp directory for an SRT-generated CA. No-op for user CAs. */
export declare function disposeMitmCA(ca: MitmCA): Promise<void>;
//# sourceMappingURL=mitm-ca.d.ts.map