import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  GetInferenceProfileRequest,
  GetInferenceProfileResponse,
} from "../models/models_1";
export { __MetadataBearer };
export { $Command };
export interface GetInferenceProfileCommandInput
  extends GetInferenceProfileRequest {}
export interface GetInferenceProfileCommandOutput
  extends GetInferenceProfileResponse,
    __MetadataBearer {}
declare const GetInferenceProfileCommand_base: {
  new (
    input: GetInferenceProfileCommandInput
  ): import("@smithy/core/client").CommandImpl<
    GetInferenceProfileCommandInput,
    GetInferenceProfileCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: GetInferenceProfileCommandInput
  ): import("@smithy/core/client").CommandImpl<
    GetInferenceProfileCommandInput,
    GetInferenceProfileCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class GetInferenceProfileCommand extends GetInferenceProfileCommand_base {
  protected static __types: {
    api: {
      input: GetInferenceProfileRequest;
      output: GetInferenceProfileResponse;
    };
    sdk: {
      input: GetInferenceProfileCommandInput;
      output: GetInferenceProfileCommandOutput;
    };
  };
}
