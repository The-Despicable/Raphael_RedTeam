import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  GetProvisionedModelThroughputRequest,
  GetProvisionedModelThroughputResponse,
} from "../models/models_1";
export { __MetadataBearer };
export { $Command };
export interface GetProvisionedModelThroughputCommandInput
  extends GetProvisionedModelThroughputRequest {}
export interface GetProvisionedModelThroughputCommandOutput
  extends GetProvisionedModelThroughputResponse,
    __MetadataBearer {}
declare const GetProvisionedModelThroughputCommand_base: {
  new (
    input: GetProvisionedModelThroughputCommandInput
  ): import("@smithy/core/client").CommandImpl<
    GetProvisionedModelThroughputCommandInput,
    GetProvisionedModelThroughputCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: GetProvisionedModelThroughputCommandInput
  ): import("@smithy/core/client").CommandImpl<
    GetProvisionedModelThroughputCommandInput,
    GetProvisionedModelThroughputCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class GetProvisionedModelThroughputCommand extends GetProvisionedModelThroughputCommand_base {
  protected static __types: {
    api: {
      input: GetProvisionedModelThroughputRequest;
      output: GetProvisionedModelThroughputResponse;
    };
    sdk: {
      input: GetProvisionedModelThroughputCommandInput;
      output: GetProvisionedModelThroughputCommandOutput;
    };
  };
}
