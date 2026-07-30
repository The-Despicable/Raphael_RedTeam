import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  ListGuardrailsRequest,
  ListGuardrailsResponse,
} from "../models/models_1";
export { __MetadataBearer };
export { $Command };
export interface ListGuardrailsCommandInput extends ListGuardrailsRequest {}
export interface ListGuardrailsCommandOutput
  extends ListGuardrailsResponse,
    __MetadataBearer {}
declare const ListGuardrailsCommand_base: {
  new (
    input: ListGuardrailsCommandInput
  ): import("@smithy/core/client").CommandImpl<
    ListGuardrailsCommandInput,
    ListGuardrailsCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    ...[input]: [] | [ListGuardrailsCommandInput]
  ): import("@smithy/core/client").CommandImpl<
    ListGuardrailsCommandInput,
    ListGuardrailsCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class ListGuardrailsCommand extends ListGuardrailsCommand_base {
  protected static __types: {
    api: {
      input: ListGuardrailsRequest;
      output: ListGuardrailsResponse;
    };
    sdk: {
      input: ListGuardrailsCommandInput;
      output: ListGuardrailsCommandOutput;
    };
  };
}
