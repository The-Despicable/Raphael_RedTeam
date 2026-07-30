import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import { AssumeRootRequest, AssumeRootResponse } from "../models/models_0";
import {
  ServiceInputTypes,
  ServiceOutputTypes,
  STSClientResolvedConfig,
} from "../STSClient";
export { __MetadataBearer };
export { $Command };
export interface AssumeRootCommandInput extends AssumeRootRequest {}
export interface AssumeRootCommandOutput
  extends AssumeRootResponse,
    __MetadataBearer {}
declare const AssumeRootCommand_base: {
  new (
    input: AssumeRootCommandInput
  ): import("@smithy/core/client").CommandImpl<
    AssumeRootCommandInput,
    AssumeRootCommandOutput,
    STSClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: AssumeRootCommandInput
  ): import("@smithy/core/client").CommandImpl<
    AssumeRootCommandInput,
    AssumeRootCommandOutput,
    STSClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class AssumeRootCommand extends AssumeRootCommand_base {
  protected static __types: {
    api: {
      input: AssumeRootRequest;
      output: AssumeRootResponse;
    };
    sdk: {
      input: AssumeRootCommandInput;
      output: AssumeRootCommandOutput;
    };
  };
}
