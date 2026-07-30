import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  ListImportedModelsRequest,
  ListImportedModelsResponse,
} from "../models/models_1";
export { __MetadataBearer };
export { $Command };
export interface ListImportedModelsCommandInput
  extends ListImportedModelsRequest {}
export interface ListImportedModelsCommandOutput
  extends ListImportedModelsResponse,
    __MetadataBearer {}
declare const ListImportedModelsCommand_base: {
  new (
    input: ListImportedModelsCommandInput
  ): import("@smithy/core/client").CommandImpl<
    ListImportedModelsCommandInput,
    ListImportedModelsCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    ...[input]: [] | [ListImportedModelsCommandInput]
  ): import("@smithy/core/client").CommandImpl<
    ListImportedModelsCommandInput,
    ListImportedModelsCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class ListImportedModelsCommand extends ListImportedModelsCommand_base {
  protected static __types: {
    api: {
      input: ListImportedModelsRequest;
      output: ListImportedModelsResponse;
    };
    sdk: {
      input: ListImportedModelsCommandInput;
      output: ListImportedModelsCommandOutput;
    };
  };
}
