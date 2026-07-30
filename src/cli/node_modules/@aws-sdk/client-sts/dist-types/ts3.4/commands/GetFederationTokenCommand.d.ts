import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  GetFederationTokenRequest,
  GetFederationTokenResponse,
} from "../models/models_0";
import {
  ServiceInputTypes,
  ServiceOutputTypes,
  STSClientResolvedConfig,
} from "../STSClient";
export { __MetadataBearer };
export { $Command };
export interface GetFederationTokenCommandInput
  extends GetFederationTokenRequest {}
export interface GetFederationTokenCommandOutput
  extends GetFederationTokenResponse,
    __MetadataBearer {}
declare const GetFederationTokenCommand_base: {
  new (
    input: GetFederationTokenCommandInput
  ): import("@smithy/core/client").CommandImpl<
    GetFederationTokenCommandInput,
    GetFederationTokenCommandOutput,
    STSClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: GetFederationTokenCommandInput
  ): import("@smithy/core/client").CommandImpl<
    GetFederationTokenCommandInput,
    GetFederationTokenCommandOutput,
    STSClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class GetFederationTokenCommand extends GetFederationTokenCommand_base {
  protected static __types: {
    api: {
      input: GetFederationTokenRequest;
      output: GetFederationTokenResponse;
    };
    sdk: {
      input: GetFederationTokenCommandInput;
      output: GetFederationTokenCommandOutput;
    };
  };
}
