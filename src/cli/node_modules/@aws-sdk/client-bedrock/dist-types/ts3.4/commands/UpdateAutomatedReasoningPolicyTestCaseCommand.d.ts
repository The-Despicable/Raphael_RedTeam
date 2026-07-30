import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  UpdateAutomatedReasoningPolicyTestCaseRequest,
  UpdateAutomatedReasoningPolicyTestCaseResponse,
} from "../models/models_0";
export { __MetadataBearer };
export { $Command };
export interface UpdateAutomatedReasoningPolicyTestCaseCommandInput
  extends UpdateAutomatedReasoningPolicyTestCaseRequest {}
export interface UpdateAutomatedReasoningPolicyTestCaseCommandOutput
  extends UpdateAutomatedReasoningPolicyTestCaseResponse,
    __MetadataBearer {}
declare const UpdateAutomatedReasoningPolicyTestCaseCommand_base: {
  new (
    input: UpdateAutomatedReasoningPolicyTestCaseCommandInput
  ): import("@smithy/core/client").CommandImpl<
    UpdateAutomatedReasoningPolicyTestCaseCommandInput,
    UpdateAutomatedReasoningPolicyTestCaseCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: UpdateAutomatedReasoningPolicyTestCaseCommandInput
  ): import("@smithy/core/client").CommandImpl<
    UpdateAutomatedReasoningPolicyTestCaseCommandInput,
    UpdateAutomatedReasoningPolicyTestCaseCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class UpdateAutomatedReasoningPolicyTestCaseCommand extends UpdateAutomatedReasoningPolicyTestCaseCommand_base {
  protected static __types: {
    api: {
      input: UpdateAutomatedReasoningPolicyTestCaseRequest;
      output: UpdateAutomatedReasoningPolicyTestCaseResponse;
    };
    sdk: {
      input: UpdateAutomatedReasoningPolicyTestCaseCommandInput;
      output: UpdateAutomatedReasoningPolicyTestCaseCommandOutput;
    };
  };
}
