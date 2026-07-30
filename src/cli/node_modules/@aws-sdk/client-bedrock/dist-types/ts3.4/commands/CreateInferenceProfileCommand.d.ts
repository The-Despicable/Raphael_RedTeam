import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  CreateInferenceProfileRequest,
  CreateInferenceProfileResponse,
} from "../models/models_1";
export { __MetadataBearer };
export { $Command };
export interface CreateInferenceProfileCommandInput
  extends CreateInferenceProfileRequest {}
export interface CreateInferenceProfileCommandOutput
  extends CreateInferenceProfileResponse,
    __MetadataBearer {}
declare const CreateInferenceProfileCommand_base: {
  new (
    input: CreateInferenceProfileCommandInput
  ): import("@smithy/core/client").CommandImpl<
    CreateInferenceProfileCommandInput,
    CreateInferenceProfileCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: CreateInferenceProfileCommandInput
  ): import("@smithy/core/client").CommandImpl<
    CreateInferenceProfileCommandInput,
    CreateInferenceProfileCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class CreateInferenceProfileCommand extends CreateInferenceProfileCommand_base {
  protected static __types: {
    api: {
      input: CreateInferenceProfileRequest;
      output: CreateInferenceProfileResponse;
    };
    sdk: {
      input: CreateInferenceProfileCommandInput;
      output: CreateInferenceProfileCommandOutput;
    };
  };
}
