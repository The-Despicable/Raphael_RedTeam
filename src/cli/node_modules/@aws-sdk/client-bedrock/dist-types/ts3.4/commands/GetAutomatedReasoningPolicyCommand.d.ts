import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  GetAutomatedReasoningPolicyRequest,
  GetAutomatedReasoningPolicyResponse,
} from "../models/models_0";
export { __MetadataBearer };
export { $Command };
export interface GetAutomatedReasoningPolicyCommandInput
  extends GetAutomatedReasoningPolicyRequest {}
export interface GetAutomatedReasoningPolicyCommandOutput
  extends GetAutomatedReasoningPolicyResponse,
    __MetadataBearer {}
declare const GetAutomatedReasoningPolicyCommand_base: {
  new (
    input: GetAutomatedReasoningPolicyCommandInput
  ): import("@smithy/core/client").CommandImpl<
    GetAutomatedReasoningPolicyCommandInput,
    GetAutomatedReasoningPolicyCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: GetAutomatedReasoningPolicyCommandInput
  ): import("@smithy/core/client").CommandImpl<
    GetAutomatedReasoningPolicyCommandInput,
    GetAutomatedReasoningPolicyCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class GetAutomatedReasoningPolicyCommand extends GetAutomatedReasoningPolicyCommand_base {
  protected static __types: {
    api: {
      input: GetAutomatedReasoningPolicyRequest;
      output: GetAutomatedReasoningPolicyResponse;
    };
    sdk: {
      input: GetAutomatedReasoningPolicyCommandInput;
      output: GetAutomatedReasoningPolicyCommandOutput;
    };
  };
}
