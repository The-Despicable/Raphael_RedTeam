export declare const isScopedPackage: (s: string) => boolean;
export declare const isTildePackage: (s: string) => boolean;
export declare const splitSpec: (specifier: string) => {
    dir: string;
    name: string;
};
