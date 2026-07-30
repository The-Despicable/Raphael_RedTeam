import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  ListInferenceProfilesRequest,
  ListInferenceProfilesResponse,
} from "../models/models_1";
export { __MetadataBearer };
export { $Command };
export interface ListInferenceProfilesCommandInput
  extends ListInferenceProfilesRequest {}
export interface ListInferenceProfilesCommandOutput
  extends ListInferenceProfilesResponse,
    __MetadataBearer {}
declare const ListInferenceProfilesCommand_base: {
  new (
    input: ListInferenceProfilesCommandInput
  ): import("@smithy/core/client").CommandImpl<
    ListInferenceProfilesCommandInput,
    ListInferenceProfilesCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    ...[input]: [] | [ListInferenceProfilesCommandInput]
  ): import("@smithy/core/client").CommandImpl<
    ListInferenceProfilesCommandInput,
    ListInferenceProfilesCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class ListInferenceProfilesCommand extends ListInferenceProfilesCommand_base {
  protected static __types: {
    api: {
      input: ListInferenceProfilesRequest;
      output: ListInferenceProfilesResponse;
    };
    sdk: {
      input: ListInferenceProfilesCommandInput;
      output: ListInferenceProfilesCommandOutput;
    };
  };
}
