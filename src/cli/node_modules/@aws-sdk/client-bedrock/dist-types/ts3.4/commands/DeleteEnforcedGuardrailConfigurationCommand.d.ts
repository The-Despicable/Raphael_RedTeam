import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  DeleteEnforcedGuardrailConfigurationRequest,
  DeleteEnforcedGuardrailConfigurationResponse,
} from "../models/models_0";
export { __MetadataBearer };
export { $Command };
export interface DeleteEnforcedGuardrailConfigurationCommandInput
  extends DeleteEnforcedGuardrailConfigurationRequest {}
export interface DeleteEnforcedGuardrailConfigurationCommandOutput
  extends DeleteEnforcedGuardrailConfigurationResponse,
    __MetadataBearer {}
declare const DeleteEnforcedGuardrailConfigurationCommand_base: {
  new (
    input: DeleteEnforcedGuardrailConfigurationCommandInput
  ): import("@smithy/core/client").CommandImpl<
    DeleteEnforcedGuardrailConfigurationCommandInput,
    DeleteEnforcedGuardrailConfigurationCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: DeleteEnforcedGuardrailConfigurationCommandInput
  ): import("@smithy/core/client").CommandImpl<
    DeleteEnforcedGuardrailConfigurationCommandInput,
    DeleteEnforcedGuardrailConfigurationCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class DeleteEnforcedGuardrailConfigurationCommand extends DeleteEnforcedGuardrailConfigurationCommand_base {
  protected static __types: {
    api: {
      input: DeleteEnforcedGuardrailConfigurationRequest;
      output: {};
    };
    sdk: {
      input: DeleteEnforcedGuardrailConfigurationCommandInput;
      output: DeleteEnforcedGuardrailConfigurationCommandOutput;
    };
  };
}
