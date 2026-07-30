import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  ListAdvancedPromptOptimizationJobsRequest,
  ListAdvancedPromptOptimizationJobsResponse,
} from "../models/models_0";
export { __MetadataBearer };
export { $Command };
export interface ListAdvancedPromptOptimizationJobsCommandInput
  extends ListAdvancedPromptOptimizationJobsRequest {}
export interface ListAdvancedPromptOptimizationJobsCommandOutput
  extends ListAdvancedPromptOptimizationJobsResponse,
    __MetadataBearer {}
declare const ListAdvancedPromptOptimizationJobsCommand_base: {
  new (
    input: ListAdvancedPromptOptimizationJobsCommandInput
  ): import("@smithy/core/client").CommandImpl<
    ListAdvancedPromptOptimizationJobsCommandInput,
    ListAdvancedPromptOptimizationJobsCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    ...[input]: [] | [ListAdvancedPromptOptimizationJobsCommandInput]
  ): import("@smithy/core/client").CommandImpl<
    ListAdvancedPromptOptimizationJobsCommandInput,
    ListAdvancedPromptOptimizationJobsCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class ListAdvancedPromptOptimizationJobsCommand extends ListAdvancedPromptOptimizationJobsCommand_base {
  protected static __types: {
    api: {
      input: ListAdvancedPromptOptimizationJobsRequest;
      output: ListAdvancedPromptOptimizationJobsResponse;
    };
    sdk: {
      input: ListAdvancedPromptOptimizationJobsCommandInput;
      output: ListAdvancedPromptOptimizationJobsCommandOutput;
    };
  };
}
