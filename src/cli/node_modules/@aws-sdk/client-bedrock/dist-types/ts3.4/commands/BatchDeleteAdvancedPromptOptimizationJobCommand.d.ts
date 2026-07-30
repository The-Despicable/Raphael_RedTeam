import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  BatchDeleteAdvancedPromptOptimizationJobRequest,
  BatchDeleteAdvancedPromptOptimizationJobResponse,
} from "../models/models_0";
export { __MetadataBearer };
export { $Command };
export interface BatchDeleteAdvancedPromptOptimizationJobCommandInput
  extends BatchDeleteAdvancedPromptOptimizationJobRequest {}
export interface BatchDeleteAdvancedPromptOptimizationJobCommandOutput
  extends BatchDeleteAdvancedPromptOptimizationJobResponse,
    __MetadataBearer {}
declare const BatchDeleteAdvancedPromptOptimizationJobCommand_base: {
  new (
    input: BatchDeleteAdvancedPromptOptimizationJobCommandInput
  ): import("@smithy/core/client").CommandImpl<
    BatchDeleteAdvancedPromptOptimizationJobCommandInput,
    BatchDeleteAdvancedPromptOptimizationJobCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: BatchDeleteAdvancedPromptOptimizationJobCommandInput
  ): import("@smithy/core/client").CommandImpl<
    BatchDeleteAdvancedPromptOptimizationJobCommandInput,
    BatchDeleteAdvancedPromptOptimizationJobCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class BatchDeleteAdvancedPromptOptimizationJobCommand extends BatchDeleteAdvancedPromptOptimizationJobCommand_base {
  protected static __types: {
    api: {
      input: BatchDeleteAdvancedPromptOptimizationJobRequest;
      output: BatchDeleteAdvancedPromptOptimizationJobResponse;
    };
    sdk: {
      input: BatchDeleteAdvancedPromptOptimizationJobCommandInput;
      output: BatchDeleteAdvancedPromptOptimizationJobCommandOutput;
    };
  };
}
