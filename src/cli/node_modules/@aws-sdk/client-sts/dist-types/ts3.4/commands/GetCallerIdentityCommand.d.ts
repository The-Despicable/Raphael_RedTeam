import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  GetCallerIdentityRequest,
  GetCallerIdentityResponse,
} from "../models/models_0";
import {
  ServiceInputTypes,
  ServiceOutputTypes,
  STSClientResolvedConfig,
} from "../STSClient";
export { __MetadataBearer };
export { $Command };
export interface GetCallerIdentityCommandInput
  extends GetCallerIdentityRequest {}
export interface GetCallerIdentityCommandOutput
  extends GetCallerIdentityResponse,
    __MetadataBearer {}
declare const GetCallerIdentityCommand_base: {
  new (
    input: GetCallerIdentityCommandInput
  ): import("@smithy/core/client").CommandImpl<
    GetCallerIdentityCommandInput,
    GetCallerIdentityCommandOutput,
    STSClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    ...[input]: [] | [GetCallerIdentityCommandInput]
  ): import("@smithy/core/client").CommandImpl<
    GetCallerIdentityCommandInput,
    GetCallerIdentityCommandOutput,
    STSClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class GetCallerIdentityCommand extends GetCallerIdentityCommand_base {
  protected static __types: {
    api: {
      input: {};
      output: GetCallerIdentityResponse;
    };
    sdk: {
      input: GetCallerIdentityCommandInput;
      output: GetCallerIdentityCommandOutput;
    };
  };
}
