import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  DeleteAutomatedReasoningPolicyTestCaseRequest,
  DeleteAutomatedReasoningPolicyTestCaseResponse,
} from "../models/models_0";
export { __MetadataBearer };
export { $Command };
export interface DeleteAutomatedReasoningPolicyTestCaseCommandInput
  extends DeleteAutomatedReasoningPolicyTestCaseRequest {}
export interface DeleteAutomatedReasoningPolicyTestCaseCommandOutput
  extends DeleteAutomatedReasoningPolicyTestCaseResponse,
    __MetadataBearer {}
declare const DeleteAutomatedReasoningPolicyTestCaseCommand_base: {
  new (
    input: DeleteAutomatedReasoningPolicyTestCaseCommandInput
  ): import("@smithy/core/client").CommandImpl<
    DeleteAutomatedReasoningPolicyTestCaseCommandInput,
    DeleteAutomatedReasoningPolicyTestCaseCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: DeleteAutomatedReasoningPolicyTestCaseCommandInput
  ): import("@smithy/core/client").CommandImpl<
    DeleteAutomatedReasoningPolicyTestCaseCommandInput,
    DeleteAutomatedReasoningPolicyTestCaseCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class DeleteAutomatedReasoningPolicyTestCaseCommand extends DeleteAutomatedReasoningPolicyTestCaseCommand_base {
  protected static __types: {
    api: {
      input: DeleteAutomatedReasoningPolicyTestCaseRequest;
      output: {};
    };
    sdk: {
      input: DeleteAutomatedReasoningPolicyTestCaseCommandInput;
      output: DeleteAutomatedReasoningPolicyTestCaseCommandOutput;
    };
  };
}
