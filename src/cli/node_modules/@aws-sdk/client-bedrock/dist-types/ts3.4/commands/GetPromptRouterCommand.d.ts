import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  GetPromptRouterRequest,
  GetPromptRouterResponse,
} from "../models/models_1";
export { __MetadataBearer };
export { $Command };
export interface GetPromptRouterCommandInput extends GetPromptRouterRequest {}
export interface GetPromptRouterCommandOutput
  extends GetPromptRouterResponse,
    __MetadataBearer {}
declare const GetPromptRouterCommand_base: {
  new (
    input: GetPromptRouterCommandInput
  ): import("@smithy/core/client").CommandImpl<
    GetPromptRouterCommandInput,
    GetPromptRouterCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: GetPromptRouterCommandInput
  ): import("@smithy/core/client").CommandImpl<
    GetPromptRouterCommandInput,
    GetPromptRouterCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class GetPromptRouterCommand extends GetPromptRouterCommand_base {
  protected static __types: {
    api: {
      input: GetPromptRouterRequest;
      output: GetPromptRouterResponse;
    };
    sdk: {
      input: GetPromptRouterCommandInput;
      output: GetPromptRouterCommandOutput;
    };
  };
}
