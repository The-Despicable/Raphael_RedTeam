import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  StopAdvancedPromptOptimizationJobRequest,
  StopAdvancedPromptOptimizationJobResponse,
} from "../models/models_0";
export { __MetadataBearer };
export { $Command };
export interface StopAdvancedPromptOptimizationJobCommandInput
  extends StopAdvancedPromptOptimizationJobRequest {}
export interface StopAdvancedPromptOptimizationJobCommandOutput
  extends StopAdvancedPromptOptimizationJobResponse,
    __MetadataBearer {}
declare const StopAdvancedPromptOptimizationJobCommand_base: {
  new (
    input: StopAdvancedPromptOptimizationJobCommandInput
  ): import("@smithy/core/client").CommandImpl<
    StopAdvancedPromptOptimizationJobCommandInput,
    StopAdvancedPromptOptimizationJobCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: StopAdvancedPromptOptimizationJobCommandInput
  ): import("@smithy/core/client").CommandImpl<
    StopAdvancedPromptOptimizationJobCommandInput,
    StopAdvancedPromptOptimizationJobCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class StopAdvancedPromptOptimizationJobCommand extends StopAdvancedPromptOptimizationJobCommand_base {
  protected static __types: {
    api: {
      input: StopAdvancedPromptOptimizationJobRequest;
      output: {};
    };
    sdk: {
      input: StopAdvancedPromptOptimizationJobCommandInput;
      output: StopAdvancedPromptOptimizationJobCommandOutput;
    };
  };
}
