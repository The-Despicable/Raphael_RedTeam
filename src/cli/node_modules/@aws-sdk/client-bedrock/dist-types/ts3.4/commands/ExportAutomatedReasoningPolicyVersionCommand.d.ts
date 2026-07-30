import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  ExportAutomatedReasoningPolicyVersionRequest,
  ExportAutomatedReasoningPolicyVersionResponse,
} from "../models/models_0";
export { __MetadataBearer };
export { $Command };
export interface ExportAutomatedReasoningPolicyVersionCommandInput
  extends ExportAutomatedReasoningPolicyVersionRequest {}
export interface ExportAutomatedReasoningPolicyVersionCommandOutput
  extends ExportAutomatedReasoningPolicyVersionResponse,
    __MetadataBearer {}
declare const ExportAutomatedReasoningPolicyVersionCommand_base: {
  new (
    input: ExportAutomatedReasoningPolicyVersionCommandInput
  ): import("@smithy/core/client").CommandImpl<
    ExportAutomatedReasoningPolicyVersionCommandInput,
    ExportAutomatedReasoningPolicyVersionCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: ExportAutomatedReasoningPolicyVersionCommandInput
  ): import("@smithy/core/client").CommandImpl<
    ExportAutomatedReasoningPolicyVersionCommandInput,
    ExportAutomatedReasoningPolicyVersionCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class ExportAutomatedReasoningPolicyVersionCommand extends ExportAutomatedReasoningPolicyVersionCommand_base {
  protected static __types: {
    api: {
      input: ExportAutomatedReasoningPolicyVersionRequest;
      output: ExportAutomatedReasoningPolicyVersionResponse;
    };
    sdk: {
      input: ExportAutomatedReasoningPolicyVersionCommandInput;
      output: ExportAutomatedReasoningPolicyVersionCommandOutput;
    };
  };
}
