import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  ListModelInvocationJobsRequest,
  ListModelInvocationJobsResponse,
} from "../models/models_1";
export { __MetadataBearer };
export { $Command };
export interface ListModelInvocationJobsCommandInput
  extends ListModelInvocationJobsRequest {}
export interface ListModelInvocationJobsCommandOutput
  extends ListModelInvocationJobsResponse,
    __MetadataBearer {}
declare const ListModelInvocationJobsCommand_base: {
  new (
    input: ListModelInvocationJobsCommandInput
  ): import("@smithy/core/client").CommandImpl<
    ListModelInvocationJobsCommandInput,
    ListModelInvocationJobsCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    ...[input]: [] | [ListModelInvocationJobsCommandInput]
  ): import("@smithy/core/client").CommandImpl<
    ListModelInvocationJobsCommandInput,
    ListModelInvocationJobsCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class ListModelInvocationJobsCommand extends ListModelInvocationJobsCommand_base {
  protected static __types: {
    api: {
      input: ListModelInvocationJobsRequest;
      output: ListModelInvocationJobsResponse;
    };
    sdk: {
      input: ListModelInvocationJobsCommandInput;
      output: ListModelInvocationJobsCommandOutput;
    };
  };
}
