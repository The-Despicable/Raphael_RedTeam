import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  CreateModelCopyJobRequest,
  CreateModelCopyJobResponse,
} from "../models/models_1";
export { __MetadataBearer };
export { $Command };
export interface CreateModelCopyJobCommandInput
  extends CreateModelCopyJobRequest {}
export interface CreateModelCopyJobCommandOutput
  extends CreateModelCopyJobResponse,
    __MetadataBearer {}
declare const CreateModelCopyJobCommand_base: {
  new (
    input: CreateModelCopyJobCommandInput
  ): import("@smithy/core/client").CommandImpl<
    CreateModelCopyJobCommandInput,
    CreateModelCopyJobCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: CreateModelCopyJobCommandInput
  ): import("@smithy/core/client").CommandImpl<
    CreateModelCopyJobCommandInput,
    CreateModelCopyJobCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class CreateModelCopyJobCommand extends CreateModelCopyJobCommand_base {
  protected static __types: {
    api: {
      input: CreateModelCopyJobRequest;
      output: CreateModelCopyJobResponse;
    };
    sdk: {
      input: CreateModelCopyJobCommandInput;
      output: CreateModelCopyJobCommandOutput;
    };
  };
}
