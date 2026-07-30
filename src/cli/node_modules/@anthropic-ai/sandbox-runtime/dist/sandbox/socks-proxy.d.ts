import type { Socks5Server } from '@pondwader/socks5-server';
import type { ResolvedParentProxy } from './parent-proxy.js';
export interface SocksProxyServerOptions {
    filter(port: number, host: string): Promise<boolean> | boolean;
    /**
     * Optional upstream HTTP proxy. When present, SOCKS CONNECT requests are
     * tunnelled through the parent's HTTP CONNECT instead of dialing directly.
     * NO_PROXY-matched hosts still connect directly.
     */
    parentProxy?: ResolvedParentProxy;
    /**
     * Per-session token (same value as the HTTP proxy's). When set, the
     * server requires SOCKS5 username/password auth and only accepts
     * user "srt" with this token as the password.
     */
    proxyAuthToken?: string;
}
export interface SocksProxyWrapper {
    server: Socks5Server;
    getPort(): number | undefined;
    listen(port: number, hostname: string): Promise<number>;
    close(): Promise<void>;
    unref(): void;
}
export declare function createSocksProxyServer(options: SocksProxyServerOptions): SocksProxyWrapper;
//# sourceMappingURL=socks-proxy.d.ts.map