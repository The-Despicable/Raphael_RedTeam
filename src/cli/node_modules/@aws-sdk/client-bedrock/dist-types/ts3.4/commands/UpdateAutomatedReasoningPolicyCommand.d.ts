import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  UpdateAutomatedReasoningPolicyRequest,
  UpdateAutomatedReasoningPolicyResponse,
} from "../models/models_0";
export { __MetadataBearer };
export { $Command };
export interface UpdateAutomatedReasoningPolicyCommandInput
  extends UpdateAutomatedReasoningPolicyRequest {}
export interface UpdateAutomatedReasoningPolicyCommandOutput
  extends UpdateAutomatedReasoningPolicyResponse,
    __MetadataBearer {}
declare const UpdateAutomatedReasoningPolicyCommand_base: {
  new (
    input: UpdateAutomatedReasoningPolicyCommandInput
  ): import("@smithy/core/client").CommandImpl<
    UpdateAutomatedReasoningPolicyCommandInput,
    UpdateAutomatedReasoningPolicyCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: UpdateAutomatedReasoningPolicyCommandInput
  ): import("@smithy/core/client").CommandImpl<
    UpdateAutomatedReasoningPolicyCommandInput,
    UpdateAutomatedReasoningPolicyCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class UpdateAutomatedReasoningPolicyCommand extends UpdateAutomatedReasoningPolicyCommand_base {
  protected static __types: {
    api: {
      input: UpdateAutomatedReasoningPolicyRequest;
      output: UpdateAutomatedReasoningPolicyResponse;
    };
    sdk: {
      input: UpdateAutomatedReasoningPolicyCommandInput;
      output: UpdateAutomatedReasoningPolicyCommandOutput;
    };
  };
}
