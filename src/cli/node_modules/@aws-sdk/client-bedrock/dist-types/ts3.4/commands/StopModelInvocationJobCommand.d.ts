import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  StopModelInvocationJobRequest,
  StopModelInvocationJobResponse,
} from "../models/models_1";
export { __MetadataBearer };
export { $Command };
export interface StopModelInvocationJobCommandInput
  extends StopModelInvocationJobRequest {}
export interface StopModelInvocationJobCommandOutput
  extends StopModelInvocationJobResponse,
    __MetadataBearer {}
declare const StopModelInvocationJobCommand_base: {
  new (
    input: StopModelInvocationJobCommandInput
  ): import("@smithy/core/client").CommandImpl<
    StopModelInvocationJobCommandInput,
    StopModelInvocationJobCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: StopModelInvocationJobCommandInput
  ): import("@smithy/core/client").CommandImpl<
    StopModelInvocationJobCommandInput,
    StopModelInvocationJobCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class StopModelInvocationJobCommand extends StopModelInvocationJobCommand_base {
  protected static __types: {
    api: {
      input: StopModelInvocationJobRequest;
      output: {};
    };
    sdk: {
      input: StopModelInvocationJobCommandInput;
      output: StopModelInvocationJobCommandOutput;
    };
  };
}
