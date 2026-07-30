import type { persist as esmPersist, restore as esmRestore, persistToFile as esmPersistToFile, restoreFromFile as esmRestoreFromFile } from './index.js';
export interface OramaPluginDataPersistenceExport {
    persist: typeof esmPersist;
    restore: typeof esmRestore;
}
export type RequireCallback = (err: Error | undefined, orama?: OramaPluginDataPersistenceExport) => void;
export declare function persist(...args: Parameters<typeof esmPersist>): ReturnType<typeof esmPersist>;
export declare function restore(...args: Parameters<typeof esmRestore>): ReturnType<typeof esmRestore>;
export declare function persistToFile(...args: Parameters<typeof esmPersistToFile>): ReturnType<typeof esmPersistToFile>;
export declare function restoreFromFile(...args: Parameters<typeof esmRestoreFromFile>): ReturnType<typeof esmRestoreFromFile>;
export declare function requireOramaPluginDataPersistence(callback: RequireCallback): void;
