import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  CreateAutomatedReasoningPolicyTestCaseRequest,
  CreateAutomatedReasoningPolicyTestCaseResponse,
} from "../models/models_0";
export { __MetadataBearer };
export { $Command };
export interface CreateAutomatedReasoningPolicyTestCaseCommandInput
  extends CreateAutomatedReasoningPolicyTestCaseRequest {}
export interface CreateAutomatedReasoningPolicyTestCaseCommandOutput
  extends CreateAutomatedReasoningPolicyTestCaseResponse,
    __MetadataBearer {}
declare const CreateAutomatedReasoningPolicyTestCaseCommand_base: {
  new (
    input: CreateAutomatedReasoningPolicyTestCaseCommandInput
  ): import("@smithy/core/client").CommandImpl<
    CreateAutomatedReasoningPolicyTestCaseCommandInput,
    CreateAutomatedReasoningPolicyTestCaseCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: CreateAutomatedReasoningPolicyTestCaseCommandInput
  ): import("@smithy/core/client").CommandImpl<
    CreateAutomatedReasoningPolicyTestCaseCommandInput,
    CreateAutomatedReasoningPolicyTestCaseCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class CreateAutomatedReasoningPolicyTestCaseCommand extends CreateAutomatedReasoningPolicyTestCaseCommand_base {
  protected static __types: {
    api: {
      input: CreateAutomatedReasoningPolicyTestCaseRequest;
      output: CreateAutomatedReasoningPolicyTestCaseResponse;
    };
    sdk: {
      input: CreateAutomatedReasoningPolicyTestCaseCommandInput;
      output: CreateAutomatedReasoningPolicyTestCaseCommandOutput;
    };
  };
}
