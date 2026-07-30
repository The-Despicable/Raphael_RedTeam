import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  DeletePromptRouterRequest,
  DeletePromptRouterResponse,
} from "../models/models_1";
export { __MetadataBearer };
export { $Command };
export interface DeletePromptRouterCommandInput
  extends DeletePromptRouterRequest {}
export interface DeletePromptRouterCommandOutput
  extends DeletePromptRouterResponse,
    __MetadataBearer {}
declare const DeletePromptRouterCommand_base: {
  new (
    input: DeletePromptRouterCommandInput
  ): import("@smithy/core/client").CommandImpl<
    DeletePromptRouterCommandInput,
    DeletePromptRouterCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: DeletePromptRouterCommandInput
  ): import("@smithy/core/client").CommandImpl<
    DeletePromptRouterCommandInput,
    DeletePromptRouterCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class DeletePromptRouterCommand extends DeletePromptRouterCommand_base {
  protected static __types: {
    api: {
      input: DeletePromptRouterRequest;
      output: {};
    };
    sdk: {
      input: DeletePromptRouterCommandInput;
      output: DeletePromptRouterCommandOutput;
    };
  };
}
