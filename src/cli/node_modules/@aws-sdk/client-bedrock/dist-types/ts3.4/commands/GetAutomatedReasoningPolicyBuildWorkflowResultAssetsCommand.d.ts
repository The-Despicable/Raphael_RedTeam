import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  GetAutomatedReasoningPolicyBuildWorkflowResultAssetsRequest,
  GetAutomatedReasoningPolicyBuildWorkflowResultAssetsResponse,
} from "../models/models_0";
export { __MetadataBearer };
export { $Command };
export interface GetAutomatedReasoningPolicyBuildWorkflowResultAssetsCommandInput
  extends GetAutomatedReasoningPolicyBuildWorkflowResultAssetsRequest {}
export interface GetAutomatedReasoningPolicyBuildWorkflowResultAssetsCommandOutput
  extends GetAutomatedReasoningPolicyBuildWorkflowResultAssetsResponse,
    __MetadataBearer {}
declare const GetAutomatedReasoningPolicyBuildWorkflowResultAssetsCommand_base: {
  new (
    input: GetAutomatedReasoningPolicyBuildWorkflowResultAssetsCommandInput
  ): import("@smithy/core/client").CommandImpl<
    GetAutomatedReasoningPolicyBuildWorkflowResultAssetsCommandInput,
    GetAutomatedReasoningPolicyBuildWorkflowResultAssetsCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: GetAutomatedReasoningPolicyBuildWorkflowResultAssetsCommandInput
  ): import("@smithy/core/client").CommandImpl<
    GetAutomatedReasoningPolicyBuildWorkflowResultAssetsCommandInput,
    GetAutomatedReasoningPolicyBuildWorkflowResultAssetsCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class GetAutomatedReasoningPolicyBuildWorkflowResultAssetsCommand extends GetAutomatedReasoningPolicyBuildWorkflowResultAssetsCommand_base {
  protected static __types: {
    api: {
      input: GetAutomatedReasoningPolicyBuildWorkflowResultAssetsRequest;
      output: GetAutomatedReasoningPolicyBuildWorkflowResultAssetsResponse;
    };
    sdk: {
      input: GetAutomatedReasoningPolicyBuildWorkflowResultAssetsCommandInput;
      output: GetAutomatedReasoningPolicyBuildWorkflowResultAssetsCommandOutput;
    };
  };
}
