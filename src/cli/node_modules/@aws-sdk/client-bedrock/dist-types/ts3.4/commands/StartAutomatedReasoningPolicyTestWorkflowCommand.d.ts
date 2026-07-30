import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  StartAutomatedReasoningPolicyTestWorkflowRequest,
  StartAutomatedReasoningPolicyTestWorkflowResponse,
} from "../models/models_0";
export { __MetadataBearer };
export { $Command };
export interface StartAutomatedReasoningPolicyTestWorkflowCommandInput
  extends StartAutomatedReasoningPolicyTestWorkflowRequest {}
export interface StartAutomatedReasoningPolicyTestWorkflowCommandOutput
  extends StartAutomatedReasoningPolicyTestWorkflowResponse,
    __MetadataBearer {}
declare const StartAutomatedReasoningPolicyTestWorkflowCommand_base: {
  new (
    input: StartAutomatedReasoningPolicyTestWorkflowCommandInput
  ): import("@smithy/core/client").CommandImpl<
    StartAutomatedReasoningPolicyTestWorkflowCommandInput,
    StartAutomatedReasoningPolicyTestWorkflowCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: StartAutomatedReasoningPolicyTestWorkflowCommandInput
  ): import("@smithy/core/client").CommandImpl<
    StartAutomatedReasoningPolicyTestWorkflowCommandInput,
    StartAutomatedReasoningPolicyTestWorkflowCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class StartAutomatedReasoningPolicyTestWorkflowCommand extends StartAutomatedReasoningPolicyTestWorkflowCommand_base {
  protected static __types: {
    api: {
      input: StartAutomatedReasoningPolicyTestWorkflowRequest;
      output: StartAutomatedReasoningPolicyTestWorkflowResponse;
    };
    sdk: {
      input: StartAutomatedReasoningPolicyTestWorkflowCommandInput;
      output: StartAutomatedReasoningPolicyTestWorkflowCommandOutput;
    };
  };
}
