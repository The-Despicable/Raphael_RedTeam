/**
 * In-process TLS termination for HTTPS traffic through the forward proxy.
 *
 * When a MitmCA is configured, the forward proxy hands CONNECT requests here
 * instead of opening an opaque byte tunnel. We terminate the client's TLS
 * with a per-host leaf cert (see mitm-leaf.ts), parse the decrypted stream
 * as HTTP/1.1, and re-issue each request upstream over a real TLS
 * connection. The optional `filterRequest` callback runs on each parsed
 * request before it is forwarded.
 */
import type { Duplex } from 'node:stream';
import type { MitmCA } from './mitm-ca.js';
import { type FilterRequestCallback } from './request-filter.js';
/**
 * True if `buf` starts with a TLS Handshake record header.
 *
 * Three bytes: content type 0x16 (Handshake) + legacy_record_version
 * 0x03,0x00–0x03. RFC 8446 §5.1 froze the record-layer version (TLS 1.3+
 * negotiate via the supported_versions extension, the wire header stays
 * ≤0x0303), so this holds for current and future TLS. Same predicate as
 * mitmproxy `starts_like_tls_record`; nginx `ssl_preread` routes on byte 0
 * alone and HAProxy `req.ssl_hello_type` reads 9 bytes to also extract the
 * handshake type — 3 is the established middle ground for "is this TLS".
 *
 * Routing heuristic, not a security check: a non-TLS stream that happens to
 * start 16 03 0x is handed to the TLS server, which then rejects it properly.
 */
export declare function looksLikeClientHello(buf: Buffer): boolean;
/**
 * Wait for the client's first post-CONNECT bytes and report whether they look
 * like a TLS ClientHello. The caller must already have written the
 * `200 Connection Established` line — clients don't send until they see it.
 *
 * Any bytes consumed here are returned in `.head` so the caller can forward
 * them to whichever downstream (terminate or opaque tunnel) it picks. The
 * socket is left paused so further bytes buffer until the downstream
 * `pipe()` resumes it.
 */
export declare function peekForClientHello(socket: Duplex, head: Buffer): Promise<{
    isTLS: boolean;
    head: Buffer;
}>;
export type TerminateTarget = {
    hostname: string;
    port: number;
    /**
     * Additional trusted CA(s) for the proxy's outbound TLS leg. Unset → system
     * roots + NODE_EXTRA_CA_CERTS. Primarily a test seam (NODE_EXTRA_CA_CERTS
     * is read at process start, so tests can't set it from inside the suite).
     */
    upstreamCA?: string | Buffer | Array<string | Buffer>;
};
/**
 * Terminate the client's TLS on `socket`, parse the decrypted HTTP/1.1
 * stream, and forward each request to `target` over a fresh upstream TLS
 * connection.
 *
 * Preconditions: the caller has already validated `target` against the
 * domain allowlist; this function does not re-check it.
 *
 * Implementation: we stand up a short-lived https.Server on a unix socket
 * and pipe the client socket through it. The Node-idiomatic alternative —
 * feeding the raw socket to a non-listening server via
 * `emit('connection', socket)` — is not implemented by Bun's https.Server,
 * and SRT runs under both runtimes. A per-connection server lets the
 * request handler close over `target` (which carries the originally-
 * requested host:port) without socket-keyed lookups.
 */
export declare function terminateAndForward(ca: MitmCA, filterRequest: FilterRequestCallback | undefined, socket: Duplex, head: Buffer, target: TerminateTarget): void;
//# sourceMappingURL=tls-terminate-proxy.d.ts.map