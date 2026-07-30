import type { SandboxDependencyCheck } from './linux-sandbox-utils.js';
/**
 * Windows sandbox backend.
 *
 * Network isolation is enforced by `srt-win.exe` — a Rust helper that
 * manages a local discriminator group, a machine-wide WFP filter set
 * keyed on that group's SID, and an `exec` subcommand that spawns the
 * target under a restricted token (group flipped deny-only) inside a
 * hardened job. The sandboxed child reaches the host only via the JS
 * http/socks proxies, which `srt-win exec` points at via env vars.
 *
 * This module is a thin wrapper around the `srt-win` CLI; all status
 * comes from live enumeration (group via `LookupAccountNameW` +
 * token-membership check; WFP via providerData-tag enumeration under
 * the configured sublayer). There is no marker file.
 *
 * Filesystem restrictions are NOT enforced on Windows yet.
 */
export declare const DEFAULT_WINDOWS_GROUP_NAME = "sandbox-runtime-net";
export declare const DEFAULT_WINDOWS_PROXY_PORT_RANGE: readonly [number, number];
/** Identifies the discriminator group either by name or by SID. */
export interface WindowsGroupRef {
    /** Local or domain group name. Default: `sandbox-runtime-net`. */
    groupName?: string;
    /**
     * Group SID in `S-1-…` form. Takes precedence over `groupName` —
     * use for domain groups or where name resolution is unreliable.
     */
    groupSid?: string;
}
export type WindowsGroupStatus = 'absent' | 'created-not-on-token' | 'ready';
export interface WindowsGroupStatusResult {
    state: WindowsGroupStatus;
    sid?: string;
    warning?: string;
    error?: string;
}
export type WindowsWfpStatus = 'absent' | 'installed';
export interface WindowsWfpStatusResult {
    state: WindowsWfpStatus;
    filters: number;
    /** `[low, high]` from the `permit-loopback` filter's tag, when present. */
    portRange?: [number, number];
}
export interface WindowsSandboxParams {
    command: string;
    group: WindowsGroupRef;
    /** JS HTTP proxy port — fed to `generateProxyEnvVars` for the returned env. */
    httpProxyPort?: number;
    /** JS SOCKS proxy port — fed to `generateProxyEnvVars` for the returned env. */
    socksProxyPort?: number;
    /** Per-session proxy auth token; embedded in proxy env URLs. */
    proxyAuthToken?: string;
    /**
     * Inner shell. `cmd` (default), `powershell`, or `pwsh`. The child's
     * post-`/c` content is **passthrough** — `&` chains, `"…"` quotes
     * exactly as written. The security boundary is at the OUTER spawn
     * (this argv is spawned with `shell:false`); the inner cmd.exe runs
     * INSIDE the sandbox so its metachars are the user's tool.
     */
    binShell?: string;
}
/**
 * Locate `srt-win.exe`. Resolution order:
 *   1. `SRT_WIN_PATH` env var (CI sets this to the freshly-built binary).
 *   2. `<repo>/vendor/srt-win/target/release/srt-win.exe` (local cargo build).
 *   3. `<repo>/dist/vendor/srt-win/target/release/srt-win.exe`
 *      (post-`npm run build` shape, when running from compiled output).
 *
 * Resolution via the optional `@anthropic-ai/sandbox-runtime-win32-*`
 * platform packages is added separately.
 *
 * @throws if none exist.
 */
export declare function getSrtWinPath(): string;
/**
 * Query the discriminator group's state in SAM and in the current
 * process's `TokenGroups`. `ready` means the group exists AND is
 * enabled in the caller's token (i.e. the logout/login dance has
 * happened). `created-not-on-token` means the install step ran but
 * a fresh logon is needed before {@link initialize} can succeed.
 */
export declare function getWindowsGroupStatus(ref: WindowsGroupRef): WindowsGroupStatusResult;
/**
 * Query the WFP filter set under the given sublayer. `installed` means
 * srt-win-tagged `permit-group` AND `block` filters are both present
 * under that sublayer. Detection is **tag-based** (providerData JSON);
 * filters installed by other tooling without the tag are not counted.
 */
export declare function getWindowsWfpStatus(opts?: {
    sublayerGuid?: string;
}): WindowsWfpStatusResult;
export interface WindowsInstallOptions extends WindowsGroupRef {
    /** Add this user (instead of the current user) to the group. */
    userSid?: string;
    /** WFP sublayer GUID. Omit for srt-win's compile-time default. */
    sublayerGuid?: string;
    /**
     * Loopback PERMIT port range. Must match what
     * `SandboxRuntimeConfig.windows.proxyPortRange` will be set to.
     * Default {@link DEFAULT_WINDOWS_PROXY_PORT_RANGE}.
     */
    proxyPortRange?: readonly [number, number];
    /**
     * Replace an existing install whose configuration differs
     * (different group SID or port range under the same sublayer).
     * Without this, install refuses with "already installed with
     * different config" rather than silently overwriting.
     */
    force?: boolean;
}
export interface WindowsInstallResult {
    /** Post-install group state. */
    group: WindowsGroupStatusResult;
    /** Post-install WFP state. */
    wfp: WindowsWfpStatusResult;
    /**
     * `true` if the user dismissed the UAC prompt. Not an error —
     * the install simply didn't happen. Re-run when the user is
     * ready to grant elevation.
     */
    cancelled?: true;
}
/**
 * One-shot install: creates the discriminator group, adds the
 * current user (or `userSid`), and installs the machine-wide WFP
 * filter set — all in a single self-elevating process (one UAC
 * prompt). Idempotent.
 *
 * Network for the calling user is **not disrupted** before the
 * required logout: while the group is absent from the token, WFP
 * filter-0 (PERMIT non-members) matches and traffic flows normally.
 * After log-out/log-in, the group is enabled in the token and
 * filter-1 (PERMIT group-enabled) takes over for the broker; only
 * `srt-win exec` children (group flipped deny-only) fall through to
 * the loopback/BLOCK filters.
 *
 * Returns the post-call group + WFP state. If the user cancels the
 * UAC prompt this returns `{cancelled: true, …}` rather than
 * throwing — cancellation is a user choice, not an error.
 *
 * @throws on group/WFP creation failure, or if filters already
 *   exist under `sublayerGuid` with different configuration and
 *   `force` is not set.
 */
export declare function installWindowsSandbox(opts?: WindowsInstallOptions): WindowsInstallResult;
/**
 * Remove the WFP filter set under `sublayerGuid` (one UAC prompt).
 * Idempotent.
 *
 * **Does NOT delete the discriminator group** — group membership is
 * persistent user state and removing it would force every user to
 * re-do the logout dance on the next install. Call
 * {@link deleteWindowsGroup} explicitly if you want full teardown.
 *
 * @returns `{cancelled: true}` if the user dismissed UAC.
 */
export declare function uninstallWindowsSandbox(opts?: {
    sublayerGuid?: string;
}): {
    cancelled?: true;
};
/**
 * Delete the discriminator group. Separate from
 * {@link uninstallWindowsSandbox} so that uninstall→reinstall
 * doesn't force a fresh logout for every member. **Requires
 * elevation.** Idempotent (no-op if the group doesn't exist).
 */
export declare function deleteWindowsGroup(ref: WindowsGroupRef): void;
/**
 * Granular primitive: create the discriminator group and add the
 * current user (or `userSid`). Most callers should use
 * {@link installWindowsSandbox} instead; this exists for
 * enterprise/CI flows that manage group and WFP separately.
 * **Requires elevation.** Idempotent.
 */
export declare function createWindowsGroup(ref: WindowsGroupRef & {
    userSid?: string;
}): void;
/**
 * Granular primitive: install the machine-wide WFP filter set
 * under `sublayerGuid` keyed on the group SID. Most callers should
 * use {@link installWindowsSandbox} instead; this exists for
 * enterprise/CI flows that manage group and WFP separately.
 * **Requires elevation.** Idempotent — re-running replaces any
 * existing srt-win-tagged filters under that sublayer.
 */
export declare function createWindowsWfp(ref: WindowsGroupRef & {
    sublayerGuid?: string;
    proxyPortRange?: readonly [number, number];
}): void;
/**
 * Build the spawn descriptor for running `command` inside the Windows
 * sandbox: an `argv` array plus the `env` to spawn it with.
 *
 * Caller MUST spawn the result with `{shell: false}` — that is the
 * security boundary that keeps untrusted bytes off the host's shell
 * (the inner `cmd.exe /c` runs INSIDE the sandbox; see
 * `vendor/srt-win/src/launch.rs` `build_cmdline` for the passthrough
 * rationale) — AND with the returned `env`.
 *
 * Proxy configuration is single-sourced by {@link generateProxyEnvVars}
 * (the same canonical builder used on macOS/Linux). `srt-win exec`
 * takes no `--http-proxy` / `--socks-proxy` flags and synthesizes no
 * proxy env; it forwards its own environment to the sandboxed child
 * verbatim. So the full proxy set is merged over the broker's
 * environment here and the child inherits it through the spawn.
 */
export declare function wrapCommandWithSandboxWindows(p: WindowsSandboxParams): {
    argv: string[];
    env: NodeJS.ProcessEnv;
};
/**
 * Install instructions, surfaced verbatim in error messages.
 * Tailored to the observed group state: if the install already
 * ran (`created-not-on-token`), only the logout is missing.
 */
export declare function windowsInstallInstructions(ref: WindowsGroupRef, sublayerGuid: string | undefined, groupState: WindowsGroupStatus): string;
/**
 * Check the Windows backend is ready to sandbox. Errors block
 * `initialize()`; warnings are informational.
 */
export declare function checkWindowsDependencies(ref: WindowsGroupRef, sublayerGuid?: string): SandboxDependencyCheck;
//# sourceMappingURL=windows-sandbox-utils.d.ts.map