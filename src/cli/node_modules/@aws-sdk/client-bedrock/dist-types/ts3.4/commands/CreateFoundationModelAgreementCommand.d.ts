import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  CreateFoundationModelAgreementRequest,
  CreateFoundationModelAgreementResponse,
} from "../models/models_1";
export { __MetadataBearer };
export { $Command };
export interface CreateFoundationModelAgreementCommandInput
  extends CreateFoundationModelAgreementRequest {}
export interface CreateFoundationModelAgreementCommandOutput
  extends CreateFoundationModelAgreementResponse,
    __MetadataBearer {}
declare const CreateFoundationModelAgreementCommand_base: {
  new (
    input: CreateFoundationModelAgreementCommandInput
  ): import("@smithy/core/client").CommandImpl<
    CreateFoundationModelAgreementCommandInput,
    CreateFoundationModelAgreementCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: CreateFoundationModelAgreementCommandInput
  ): import("@smithy/core/client").CommandImpl<
    CreateFoundationModelAgreementCommandInput,
    CreateFoundationModelAgreementCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class CreateFoundationModelAgreementCommand extends CreateFoundationModelAgreementCommand_base {
  protected static __types: {
    api: {
      input: CreateFoundationModelAgreementRequest;
      output: CreateFoundationModelAgreementResponse;
    };
    sdk: {
      input: CreateFoundationModelAgreementCommandInput;
      output: CreateFoundationModelAgreementCommandOutput;
    };
  };
}
