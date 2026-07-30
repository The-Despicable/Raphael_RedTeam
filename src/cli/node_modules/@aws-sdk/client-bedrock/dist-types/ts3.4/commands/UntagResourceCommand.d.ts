import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  UntagResourceRequest,
  UntagResourceResponse,
} from "../models/models_1";
export { __MetadataBearer };
export { $Command };
export interface UntagResourceCommandInput extends UntagResourceRequest {}
export interface UntagResourceCommandOutput
  extends UntagResourceResponse,
    __MetadataBearer {}
declare const UntagResourceCommand_base: {
  new (
    input: UntagResourceCommandInput
  ): import("@smithy/core/client").CommandImpl<
    UntagResourceCommandInput,
    UntagResourceCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: UntagResourceCommandInput
  ): import("@smithy/core/client").CommandImpl<
    UntagResourceCommandInput,
    UntagResourceCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class UntagResourceCommand extends UntagResourceCommand_base {
  protected static __types: {
    api: {
      input: UntagResourceRequest;
      output: {};
    };
    sdk: {
      input: UntagResourceCommandInput;
      output: UntagResourceCommandOutput;
    };
  };
}
