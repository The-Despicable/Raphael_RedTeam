import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  CreateProvisionedModelThroughputRequest,
  CreateProvisionedModelThroughputResponse,
} from "../models/models_1";
export { __MetadataBearer };
export { $Command };
export interface CreateProvisionedModelThroughputCommandInput
  extends CreateProvisionedModelThroughputRequest {}
export interface CreateProvisionedModelThroughputCommandOutput
  extends CreateProvisionedModelThroughputResponse,
    __MetadataBearer {}
declare const CreateProvisionedModelThroughputCommand_base: {
  new (
    input: CreateProvisionedModelThroughputCommandInput
  ): import("@smithy/core/client").CommandImpl<
    CreateProvisionedModelThroughputCommandInput,
    CreateProvisionedModelThroughputCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: CreateProvisionedModelThroughputCommandInput
  ): import("@smithy/core/client").CommandImpl<
    CreateProvisionedModelThroughputCommandInput,
    CreateProvisionedModelThroughputCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class CreateProvisionedModelThroughputCommand extends CreateProvisionedModelThroughputCommand_base {
  protected static __types: {
    api: {
      input: CreateProvisionedModelThroughputRequest;
      output: CreateProvisionedModelThroughputResponse;
    };
    sdk: {
      input: CreateProvisionedModelThroughputCommandInput;
      output: CreateProvisionedModelThroughputCommandOutput;
    };
  };
}
