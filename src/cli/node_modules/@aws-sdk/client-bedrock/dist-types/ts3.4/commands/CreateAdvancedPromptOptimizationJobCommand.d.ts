import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  CreateAdvancedPromptOptimizationJobRequest,
  CreateAdvancedPromptOptimizationJobResponse,
} from "../models/models_0";
export { __MetadataBearer };
export { $Command };
export interface CreateAdvancedPromptOptimizationJobCommandInput
  extends CreateAdvancedPromptOptimizationJobRequest {}
export interface CreateAdvancedPromptOptimizationJobCommandOutput
  extends CreateAdvancedPromptOptimizationJobResponse,
    __MetadataBearer {}
declare const CreateAdvancedPromptOptimizationJobCommand_base: {
  new (
    input: CreateAdvancedPromptOptimizationJobCommandInput
  ): import("@smithy/core/client").CommandImpl<
    CreateAdvancedPromptOptimizationJobCommandInput,
    CreateAdvancedPromptOptimizationJobCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: CreateAdvancedPromptOptimizationJobCommandInput
  ): import("@smithy/core/client").CommandImpl<
    CreateAdvancedPromptOptimizationJobCommandInput,
    CreateAdvancedPromptOptimizationJobCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class CreateAdvancedPromptOptimizationJobCommand extends CreateAdvancedPromptOptimizationJobCommand_base {
  protected static __types: {
    api: {
      input: CreateAdvancedPromptOptimizationJobRequest;
      output: CreateAdvancedPromptOptimizationJobResponse;
    };
    sdk: {
      input: CreateAdvancedPromptOptimizationJobCommandInput;
      output: CreateAdvancedPromptOptimizationJobCommandOutput;
    };
  };
}
