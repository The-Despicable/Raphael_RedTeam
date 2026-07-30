/**
 * Per-host leaf certificate minter for the in-process TLS-terminating proxy.
 *
 * Given a MitmCA (see mitm-ca.ts), mints a leaf certificate for a specific
 * hostname on first use and caches it for the lifetime of that CA instance.
 * The leaf is signed by the CA and carries SAN=DNS:<host> (or IP:<addr>),
 * so a client that trusts the CA will accept it for that host.
 */
import { type SecureContext } from 'node:tls';
import type { MitmCA } from './mitm-ca.js';
export type LeafCert = {
    /** Leaf cert PEM followed by the CA cert PEM (full chain). */
    certPem: string;
    /** Leaf private key PEM. */
    keyPem: string;
};
/**
 * Mint (or return cached) an RSA-2048 leaf cert for `hostname`, signed by `ca`.
 * The cache lives on `ca.leafCerts`.
 */
export declare function mintLeafCert(ca: MitmCA, hostname: string): LeafCert;
/**
 * Mint-or-cache a Node TLS SecureContext for `hostname`. Intended as the
 * SNICallback target in the terminating proxy. The cache lives on
 * `ca.secureContexts`.
 */
export declare function secureContextFor(ca: MitmCA, hostname: string): SecureContext;
//# sourceMappingURL=mitm-leaf.d.ts.map