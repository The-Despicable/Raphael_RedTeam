import type { Socket } from 'node:net';
import type { Duplex } from 'node:stream';
import type { Server } from 'node:http';
import type { MitmCA } from './mitm-ca.js';
import { type FilterRequestCallback } from './request-filter.js';
import type { ResolvedParentProxy } from './parent-proxy.js';
export interface HttpProxyServerOptions {
    filter(port: number, host: string, socket: Socket | Duplex): Promise<boolean> | boolean;
    /**
     * Optional function to get the MITM proxy socket path for a given host.
     * If returns a socket path, the request will be routed through that MITM proxy.
     * If returns undefined, the request will be handled directly.
     */
    getMitmSocketPath?(host: string): string | undefined;
    /**
     * If present, CONNECT requests are TLS-terminated in-process and the
     * decrypted HTTP forwarded upstream over real TLS, instead of opening an
     * opaque byte tunnel. Mutually exclusive with getMitmSocketPath at the
     * config layer (sandbox-manager rejects both being set).
     */
    mitmCA?: MitmCA;
    /**
     * Per-request filter; runs on plain-HTTP proxy requests and on terminated
     * HTTPS requests. See request-filter.ts.
     */
    filterRequest?: FilterRequestCallback;
    /**
     * Additional trusted CA(s) for the terminating proxy's outbound TLS leg.
     * Unset → system roots + NODE_EXTRA_CA_CERTS. Primarily a test seam.
     */
    tlsTerminateUpstreamCA?: string | Buffer | Array<string | Buffer>;
    /**
     * Optional upstream HTTP proxy. When present, direct-connect traffic (i.e.
     * not routed via mitmProxy) is tunnelled through this parent instead of
     * connecting directly. NO_PROXY-matched hosts still connect directly.
     */
    parentProxy?: ResolvedParentProxy;
    /**
     * Per-session bearer token. When set, every CONNECT and absolute-URI
     * request must carry `Proxy-Authorization: Basic base64("srt:<token>")`
     * or it gets a 407. Without this, any host process can dial 127.0.0.1
     * and reach the filter callback.
     */
    proxyAuthToken?: string;
}
export declare function createHttpProxyServer(options: HttpProxyServerOptions): Server;
//# sourceMappingURL=http-proxy.d.ts.map