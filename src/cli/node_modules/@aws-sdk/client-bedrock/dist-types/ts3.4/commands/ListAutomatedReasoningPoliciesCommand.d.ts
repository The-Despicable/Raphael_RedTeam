import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  ListAutomatedReasoningPoliciesRequest,
  ListAutomatedReasoningPoliciesResponse,
} from "../models/models_0";
export { __MetadataBearer };
export { $Command };
export interface ListAutomatedReasoningPoliciesCommandInput
  extends ListAutomatedReasoningPoliciesRequest {}
export interface ListAutomatedReasoningPoliciesCommandOutput
  extends ListAutomatedReasoningPoliciesResponse,
    __MetadataBearer {}
declare const ListAutomatedReasoningPoliciesCommand_base: {
  new (
    input: ListAutomatedReasoningPoliciesCommandInput
  ): import("@smithy/core/client").CommandImpl<
    ListAutomatedReasoningPoliciesCommandInput,
    ListAutomatedReasoningPoliciesCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    ...[input]: [] | [ListAutomatedReasoningPoliciesCommandInput]
  ): import("@smithy/core/client").CommandImpl<
    ListAutomatedReasoningPoliciesCommandInput,
    ListAutomatedReasoningPoliciesCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class ListAutomatedReasoningPoliciesCommand extends ListAutomatedReasoningPoliciesCommand_base {
  protected static __types: {
    api: {
      input: ListAutomatedReasoningPoliciesRequest;
      output: ListAutomatedReasoningPoliciesResponse;
    };
    sdk: {
      input: ListAutomatedReasoningPoliciesCommandInput;
      output: ListAutomatedReasoningPoliciesCommandOutput;
    };
  };
}
