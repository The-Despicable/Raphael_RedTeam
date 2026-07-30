import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  DeleteFoundationModelAgreementRequest,
  DeleteFoundationModelAgreementResponse,
} from "../models/models_1";
export { __MetadataBearer };
export { $Command };
export interface DeleteFoundationModelAgreementCommandInput
  extends DeleteFoundationModelAgreementRequest {}
export interface DeleteFoundationModelAgreementCommandOutput
  extends DeleteFoundationModelAgreementResponse,
    __MetadataBearer {}
declare const DeleteFoundationModelAgreementCommand_base: {
  new (
    input: DeleteFoundationModelAgreementCommandInput
  ): import("@smithy/core/client").CommandImpl<
    DeleteFoundationModelAgreementCommandInput,
    DeleteFoundationModelAgreementCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: DeleteFoundationModelAgreementCommandInput
  ): import("@smithy/core/client").CommandImpl<
    DeleteFoundationModelAgreementCommandInput,
    DeleteFoundationModelAgreementCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class DeleteFoundationModelAgreementCommand extends DeleteFoundationModelAgreementCommand_base {
  protected static __types: {
    api: {
      input: DeleteFoundationModelAgreementRequest;
      output: {};
    };
    sdk: {
      input: DeleteFoundationModelAgreementCommandInput;
      output: DeleteFoundationModelAgreementCommandOutput;
    };
  };
}
