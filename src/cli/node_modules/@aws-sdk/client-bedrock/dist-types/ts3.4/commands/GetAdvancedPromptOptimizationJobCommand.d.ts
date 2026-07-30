import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  GetAdvancedPromptOptimizationJobRequest,
  GetAdvancedPromptOptimizationJobResponse,
} from "../models/models_0";
export { __MetadataBearer };
export { $Command };
export interface GetAdvancedPromptOptimizationJobCommandInput
  extends GetAdvancedPromptOptimizationJobRequest {}
export interface GetAdvancedPromptOptimizationJobCommandOutput
  extends GetAdvancedPromptOptimizationJobResponse,
    __MetadataBearer {}
declare const GetAdvancedPromptOptimizationJobCommand_base: {
  new (
    input: GetAdvancedPromptOptimizationJobCommandInput
  ): import("@smithy/core/client").CommandImpl<
    GetAdvancedPromptOptimizationJobCommandInput,
    GetAdvancedPromptOptimizationJobCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: GetAdvancedPromptOptimizationJobCommandInput
  ): import("@smithy/core/client").CommandImpl<
    GetAdvancedPromptOptimizationJobCommandInput,
    GetAdvancedPromptOptimizationJobCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class GetAdvancedPromptOptimizationJobCommand extends GetAdvancedPromptOptimizationJobCommand_base {
  protected static __types: {
    api: {
      input: GetAdvancedPromptOptimizationJobRequest;
      output: GetAdvancedPromptOptimizationJobResponse;
    };
    sdk: {
      input: GetAdvancedPromptOptimizationJobCommandInput;
      output: GetAdvancedPromptOptimizationJobCommandOutput;
    };
  };
}
