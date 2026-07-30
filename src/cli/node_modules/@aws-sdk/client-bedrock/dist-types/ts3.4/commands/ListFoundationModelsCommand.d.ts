import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  ListFoundationModelsRequest,
  ListFoundationModelsResponse,
} from "../models/models_1";
export { __MetadataBearer };
export { $Command };
export interface ListFoundationModelsCommandInput
  extends ListFoundationModelsRequest {}
export interface ListFoundationModelsCommandOutput
  extends ListFoundationModelsResponse,
    __MetadataBearer {}
declare const ListFoundationModelsCommand_base: {
  new (
    input: ListFoundationModelsCommandInput
  ): import("@smithy/core/client").CommandImpl<
    ListFoundationModelsCommandInput,
    ListFoundationModelsCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    ...[input]: [] | [ListFoundationModelsCommandInput]
  ): import("@smithy/core/client").CommandImpl<
    ListFoundationModelsCommandInput,
    ListFoundationModelsCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class ListFoundationModelsCommand extends ListFoundationModelsCommand_base {
  protected static __types: {
    api: {
      input: ListFoundationModelsRequest;
      output: ListFoundationModelsResponse;
    };
    sdk: {
      input: ListFoundationModelsCommandInput;
      output: ListFoundationModelsCommandOutput;
    };
  };
}
