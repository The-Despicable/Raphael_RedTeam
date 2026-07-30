/**
 * Request-level filter hook for the forward proxy.
 *
 * Library consumers supply a `filterRequest` callback via
 * `network.filterRequest`. It receives the parsed HTTP request (web-standard
 * `Request`) and returns a decision. Applies to plain HTTP through the proxy
 * and, when `tlsTerminate` is configured, to terminated HTTPS. The proxy
 * enforces the decision; the library does not bless any matching DSL.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import { Readable } from 'node:stream';
export type RequestDecision = {
    action: 'allow' | 'deny';
    /**
     * Human-readable reason. For denials this is surfaced to the sandboxed
     * client in the response body so the agent can tell a policy block from a
     * network failure.
     */
    reason?: string;
};
/**
 * Called once per HTTP request that the proxy parses.
 *
 * - `request` is a web-standard `Request`: method, URL, headers, and a lazy
 *   `request.body` stream (one branch of a tee — reading it does not consume
 *   the bytes that get forwarded upstream). `request.signal` aborts when the
 *   client disconnects.
 * - **Throwing or rejecting denies the request.** This is the failure
 *   contract for a security boundary: a buggy policy fails closed.
 */
export type FilterRequestCallback = (request: Request) => Promise<RequestDecision>;
/**
 * Build a `Request`, run the callback, and if denied write the 403 response
 * and return `null`. On allow, returns the body stream the caller must pipe
 * upstream — this is the original `IncomingMessage` when no tee was needed
 * (GET/HEAD/OPTIONS), or the upstream-side branch of the tee otherwise.
 * Callers must pipe the returned stream (not `req`) to the outbound request.
 *
 * For methods that carry a body, `req` is converted to a web stream and
 * `tee()`'d: one branch goes to the callback's `Request.body`, the other is
 * returned for the caller to forward. If the callback never reads its
 * branch, we cancel it after the decision so the tee does not buffer the
 * entire upload.
 */
export declare function decideAndRespond(filterRequest: FilterRequestCallback, req: IncomingMessage, res: ServerResponse, url: string, signal: AbortSignal): Promise<Readable | null>;
//# sourceMappingURL=request-filter.d.ts.map