import type { getDefaultFileName as esmGetDefaultFileName, persistToFile as esmPersistToFile, restoreFromFile as esmRestoreFromFile } from './server.js';
export interface OramaPluginDataPersistenceExport {
    getDefaultFileName: typeof esmGetDefaultFileName;
    persistToFile: typeof esmPersistToFile;
    restoreFromFile: typeof esmRestoreFromFile;
}
export type RequireCallback = (err: Error | undefined, orama?: OramaPluginDataPersistenceExport) => void;
export declare function getDefaultFileName(...args: Parameters<typeof esmGetDefaultFileName>): ReturnType<typeof esmGetDefaultFileName>;
export declare function persistToFile(...args: Parameters<typeof esmPersistToFile>): ReturnType<typeof esmPersistToFile>;
export declare function restoreFromFile(...args: Parameters<typeof esmRestoreFromFile>): ReturnType<typeof esmRestoreFromFile>;
