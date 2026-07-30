export { SandboxManager } from './sandbox/sandbox-manager.js';
export { SandboxViolationStore } from './sandbox/sandbox-violation-store.js';
export type { SandboxRuntimeConfig, NetworkConfig, FilesystemConfig, IgnoreViolationsConfig, } from './sandbox/sandbox-config.js';
export { SandboxRuntimeConfigSchema, NetworkConfigSchema, FilesystemConfigSchema, IgnoreViolationsConfigSchema, RipgrepConfigSchema, } from './sandbox/sandbox-config.js';
export type { SandboxAskCallback, FsReadRestrictionConfig, FsWriteRestrictionConfig, NetworkRestrictionConfig, NetworkHostPattern, } from './sandbox/sandbox-schemas.js';
export type { FilterRequestCallback, RequestDecision, } from './sandbox/request-filter.js';
export type { SandboxViolationEvent } from './sandbox/macos-sandbox-utils.js';
export { type SandboxDependencyCheck } from './sandbox/linux-sandbox-utils.js';
export { getSrtWinPath, getWindowsGroupStatus, getWindowsWfpStatus, installWindowsSandbox, uninstallWindowsSandbox, createWindowsGroup, deleteWindowsGroup, createWindowsWfp, windowsInstallInstructions, DEFAULT_WINDOWS_GROUP_NAME, DEFAULT_WINDOWS_PROXY_PORT_RANGE, } from './sandbox/windows-sandbox-utils.js';
export type { WindowsGroupRef, WindowsInstallOptions, WindowsInstallResult, WindowsGroupStatus, WindowsGroupStatusResult, WindowsWfpStatus, WindowsWfpStatusResult, } from './sandbox/windows-sandbox-utils.js';
export type { WindowsConfig } from './sandbox/sandbox-config.js';
export { WindowsConfigSchema } from './sandbox/sandbox-config.js';
export { getDefaultWritePaths } from './sandbox/sandbox-utils.js';
export { getWslVersion } from './utils/platform.js';
export type { Platform } from './utils/platform.js';
//# sourceMappingURL=index.d.ts.map