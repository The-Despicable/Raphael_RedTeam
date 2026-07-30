import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  ListFoundationModelAgreementOffersRequest,
  ListFoundationModelAgreementOffersResponse,
} from "../models/models_1";
export { __MetadataBearer };
export { $Command };
export interface ListFoundationModelAgreementOffersCommandInput
  extends ListFoundationModelAgreementOffersRequest {}
export interface ListFoundationModelAgreementOffersCommandOutput
  extends ListFoundationModelAgreementOffersResponse,
    __MetadataBearer {}
declare const ListFoundationModelAgreementOffersCommand_base: {
  new (
    input: ListFoundationModelAgreementOffersCommandInput
  ): import("@smithy/core/client").CommandImpl<
    ListFoundationModelAgreementOffersCommandInput,
    ListFoundationModelAgreementOffersCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: ListFoundationModelAgreementOffersCommandInput
  ): import("@smithy/core/client").CommandImpl<
    ListFoundationModelAgreementOffersCommandInput,
    ListFoundationModelAgreementOffersCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class ListFoundationModelAgreementOffersCommand extends ListFoundationModelAgreementOffersCommand_base {
  protected static __types: {
    api: {
      input: ListFoundationModelAgreementOffersRequest;
      output: ListFoundationModelAgreementOffersResponse;
    };
    sdk: {
      input: ListFoundationModelAgreementOffersCommandInput;
      output: ListFoundationModelAgreementOffersCommandOutput;
    };
  };
}
