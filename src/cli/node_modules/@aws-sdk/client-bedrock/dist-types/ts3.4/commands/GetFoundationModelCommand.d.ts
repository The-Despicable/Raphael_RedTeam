import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  GetFoundationModelRequest,
  GetFoundationModelResponse,
} from "../models/models_1";
export { __MetadataBearer };
export { $Command };
export interface GetFoundationModelCommandInput
  extends GetFoundationModelRequest {}
export interface GetFoundationModelCommandOutput
  extends GetFoundationModelResponse,
    __MetadataBearer {}
declare const GetFoundationModelCommand_base: {
  new (
    input: GetFoundationModelCommandInput
  ): import("@smithy/core/client").CommandImpl<
    GetFoundationModelCommandInput,
    GetFoundationModelCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: GetFoundationModelCommandInput
  ): import("@smithy/core/client").CommandImpl<
    GetFoundationModelCommandInput,
    GetFoundationModelCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class GetFoundationModelCommand extends GetFoundationModelCommand_base {
  protected static __types: {
    api: {
      input: GetFoundationModelRequest;
      output: GetFoundationModelResponse;
    };
    sdk: {
      input: GetFoundationModelCommandInput;
      output: GetFoundationModelCommandOutput;
    };
  };
}
