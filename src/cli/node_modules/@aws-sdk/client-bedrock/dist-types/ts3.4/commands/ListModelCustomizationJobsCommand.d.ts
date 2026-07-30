import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  ListModelCustomizationJobsRequest,
  ListModelCustomizationJobsResponse,
} from "../models/models_1";
export { __MetadataBearer };
export { $Command };
export interface ListModelCustomizationJobsCommandInput
  extends ListModelCustomizationJobsRequest {}
export interface ListModelCustomizationJobsCommandOutput
  extends ListModelCustomizationJobsResponse,
    __MetadataBearer {}
declare const ListModelCustomizationJobsCommand_base: {
  new (
    input: ListModelCustomizationJobsCommandInput
  ): import("@smithy/core/client").CommandImpl<
    ListModelCustomizationJobsCommandInput,
    ListModelCustomizationJobsCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    ...[input]: [] | [ListModelCustomizationJobsCommandInput]
  ): import("@smithy/core/client").CommandImpl<
    ListModelCustomizationJobsCommandInput,
    ListModelCustomizationJobsCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class ListModelCustomizationJobsCommand extends ListModelCustomizationJobsCommand_base {
  protected static __types: {
    api: {
      input: ListModelCustomizationJobsRequest;
      output: ListModelCustomizationJobsResponse;
    };
    sdk: {
      input: ListModelCustomizationJobsCommandInput;
      output: ListModelCustomizationJobsCommandOutput;
    };
  };
}
