import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  ListAutomatedReasoningPolicyTestCasesRequest,
  ListAutomatedReasoningPolicyTestCasesResponse,
} from "../models/models_0";
export { __MetadataBearer };
export { $Command };
export interface ListAutomatedReasoningPolicyTestCasesCommandInput
  extends ListAutomatedReasoningPolicyTestCasesRequest {}
export interface ListAutomatedReasoningPolicyTestCasesCommandOutput
  extends ListAutomatedReasoningPolicyTestCasesResponse,
    __MetadataBearer {}
declare const ListAutomatedReasoningPolicyTestCasesCommand_base: {
  new (
    input: ListAutomatedReasoningPolicyTestCasesCommandInput
  ): import("@smithy/core/client").CommandImpl<
    ListAutomatedReasoningPolicyTestCasesCommandInput,
    ListAutomatedReasoningPolicyTestCasesCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: ListAutomatedReasoningPolicyTestCasesCommandInput
  ): import("@smithy/core/client").CommandImpl<
    ListAutomatedReasoningPolicyTestCasesCommandInput,
    ListAutomatedReasoningPolicyTestCasesCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class ListAutomatedReasoningPolicyTestCasesCommand extends ListAutomatedReasoningPolicyTestCasesCommand_base {
  protected static __types: {
    api: {
      input: ListAutomatedReasoningPolicyTestCasesRequest;
      output: ListAutomatedReasoningPolicyTestCasesResponse;
    };
    sdk: {
      input: ListAutomatedReasoningPolicyTestCasesCommandInput;
      output: ListAutomatedReasoningPolicyTestCasesCommandOutput;
    };
  };
}
