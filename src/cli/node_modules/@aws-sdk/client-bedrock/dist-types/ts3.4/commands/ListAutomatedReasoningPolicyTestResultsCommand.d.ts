import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  ListAutomatedReasoningPolicyTestResultsRequest,
  ListAutomatedReasoningPolicyTestResultsResponse,
} from "../models/models_0";
export { __MetadataBearer };
export { $Command };
export interface ListAutomatedReasoningPolicyTestResultsCommandInput
  extends ListAutomatedReasoningPolicyTestResultsRequest {}
export interface ListAutomatedReasoningPolicyTestResultsCommandOutput
  extends ListAutomatedReasoningPolicyTestResultsResponse,
    __MetadataBearer {}
declare const ListAutomatedReasoningPolicyTestResultsCommand_base: {
  new (
    input: ListAutomatedReasoningPolicyTestResultsCommandInput
  ): import("@smithy/core/client").CommandImpl<
    ListAutomatedReasoningPolicyTestResultsCommandInput,
    ListAutomatedReasoningPolicyTestResultsCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: ListAutomatedReasoningPolicyTestResultsCommandInput
  ): import("@smithy/core/client").CommandImpl<
    ListAutomatedReasoningPolicyTestResultsCommandInput,
    ListAutomatedReasoningPolicyTestResultsCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class ListAutomatedReasoningPolicyTestResultsCommand extends ListAutomatedReasoningPolicyTestResultsCommand_base {
  protected static __types: {
    api: {
      input: ListAutomatedReasoningPolicyTestResultsRequest;
      output: ListAutomatedReasoningPolicyTestResultsResponse;
    };
    sdk: {
      input: ListAutomatedReasoningPolicyTestResultsCommandInput;
      output: ListAutomatedReasoningPolicyTestResultsCommandOutput;
    };
  };
}
