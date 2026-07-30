import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  StartAutomatedReasoningPolicyBuildWorkflowRequest,
  StartAutomatedReasoningPolicyBuildWorkflowResponse,
} from "../models/models_0";
export { __MetadataBearer };
export { $Command };
export interface StartAutomatedReasoningPolicyBuildWorkflowCommandInput
  extends StartAutomatedReasoningPolicyBuildWorkflowRequest {}
export interface StartAutomatedReasoningPolicyBuildWorkflowCommandOutput
  extends StartAutomatedReasoningPolicyBuildWorkflowResponse,
    __MetadataBearer {}
declare const StartAutomatedReasoningPolicyBuildWorkflowCommand_base: {
  new (
    input: StartAutomatedReasoningPolicyBuildWorkflowCommandInput
  ): import("@smithy/core/client").CommandImpl<
    StartAutomatedReasoningPolicyBuildWorkflowCommandInput,
    StartAutomatedReasoningPolicyBuildWorkflowCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: StartAutomatedReasoningPolicyBuildWorkflowCommandInput
  ): import("@smithy/core/client").CommandImpl<
    StartAutomatedReasoningPolicyBuildWorkflowCommandInput,
    StartAutomatedReasoningPolicyBuildWorkflowCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class StartAutomatedReasoningPolicyBuildWorkflowCommand extends StartAutomatedReasoningPolicyBuildWorkflowCommand_base {
  protected static __types: {
    api: {
      input: StartAutomatedReasoningPolicyBuildWorkflowRequest;
      output: StartAutomatedReasoningPolicyBuildWorkflowResponse;
    };
    sdk: {
      input: StartAutomatedReasoningPolicyBuildWorkflowCommandInput;
      output: StartAutomatedReasoningPolicyBuildWorkflowCommandOutput;
    };
  };
}
