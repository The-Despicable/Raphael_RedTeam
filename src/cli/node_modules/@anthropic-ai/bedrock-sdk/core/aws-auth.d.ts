import { AwsCredentialIdentityProvider } from '@smithy/types';
import { MergedRequestInit } from "../internal/types.js";
export type AuthProps = {
    url: string;
    regionName: string;
    serviceName: string;
    awsAccessKey: string | null | undefined;
    awsSecretAccessKey: string | null | undefined;
    awsSessionToken: string | null | undefined;
    awsProfile?: string | null | undefined;
    fetchOptions?: MergedRequestInit | undefined;
    providerChainResolver?: (() => Promise<AwsCredentialIdentityProvider>) | null;
};
export declare const getAuthHeaders: (req: RequestInit, props: AuthProps) => Promise<Record<string, string>>;
//# sourceMappingURL=aws-auth.d.ts.map