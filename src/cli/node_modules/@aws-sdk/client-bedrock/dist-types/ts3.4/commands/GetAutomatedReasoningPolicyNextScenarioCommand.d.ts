import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  GetAutomatedReasoningPolicyNextScenarioRequest,
  GetAutomatedReasoningPolicyNextScenarioResponse,
} from "../models/models_0";
export { __MetadataBearer };
export { $Command };
export interface GetAutomatedReasoningPolicyNextScenarioCommandInput
  extends GetAutomatedReasoningPolicyNextScenarioRequest {}
export interface GetAutomatedReasoningPolicyNextScenarioCommandOutput
  extends GetAutomatedReasoningPolicyNextScenarioResponse,
    __MetadataBearer {}
declare const GetAutomatedReasoningPolicyNextScenarioCommand_base: {
  new (
    input: GetAutomatedReasoningPolicyNextScenarioCommandInput
  ): import("@smithy/core/client").CommandImpl<
    GetAutomatedReasoningPolicyNextScenarioCommandInput,
    GetAutomatedReasoningPolicyNextScenarioCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: GetAutomatedReasoningPolicyNextScenarioCommandInput
  ): import("@smithy/core/client").CommandImpl<
    GetAutomatedReasoningPolicyNextScenarioCommandInput,
    GetAutomatedReasoningPolicyNextScenarioCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class GetAutomatedReasoningPolicyNextScenarioCommand extends GetAutomatedReasoningPolicyNextScenarioCommand_base {
  protected static __types: {
    api: {
      input: GetAutomatedReasoningPolicyNextScenarioRequest;
      output: GetAutomatedReasoningPolicyNextScenarioResponse;
    };
    sdk: {
      input: GetAutomatedReasoningPolicyNextScenarioCommandInput;
      output: GetAutomatedReasoningPolicyNextScenarioCommandOutput;
    };
  };
}
