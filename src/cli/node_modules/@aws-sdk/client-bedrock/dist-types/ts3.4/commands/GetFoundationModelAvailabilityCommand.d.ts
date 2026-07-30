import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  GetFoundationModelAvailabilityRequest,
  GetFoundationModelAvailabilityResponse,
} from "../models/models_1";
export { __MetadataBearer };
export { $Command };
export interface GetFoundationModelAvailabilityCommandInput
  extends GetFoundationModelAvailabilityRequest {}
export interface GetFoundationModelAvailabilityCommandOutput
  extends GetFoundationModelAvailabilityResponse,
    __MetadataBearer {}
declare const GetFoundationModelAvailabilityCommand_base: {
  new (
    input: GetFoundationModelAvailabilityCommandInput
  ): import("@smithy/core/client").CommandImpl<
    GetFoundationModelAvailabilityCommandInput,
    GetFoundationModelAvailabilityCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: GetFoundationModelAvailabilityCommandInput
  ): import("@smithy/core/client").CommandImpl<
    GetFoundationModelAvailabilityCommandInput,
    GetFoundationModelAvailabilityCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class GetFoundationModelAvailabilityCommand extends GetFoundationModelAvailabilityCommand_base {
  protected static __types: {
    api: {
      input: GetFoundationModelAvailabilityRequest;
      output: GetFoundationModelAvailabilityResponse;
    };
    sdk: {
      input: GetFoundationModelAvailabilityCommandInput;
      output: GetFoundationModelAvailabilityCommandOutput;
    };
  };
}
