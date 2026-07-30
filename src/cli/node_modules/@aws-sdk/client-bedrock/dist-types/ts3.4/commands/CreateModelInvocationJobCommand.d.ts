import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  CreateModelInvocationJobRequest,
  CreateModelInvocationJobResponse,
} from "../models/models_1";
export { __MetadataBearer };
export { $Command };
export interface CreateModelInvocationJobCommandInput
  extends CreateModelInvocationJobRequest {}
export interface CreateModelInvocationJobCommandOutput
  extends CreateModelInvocationJobResponse,
    __MetadataBearer {}
declare const CreateModelInvocationJobCommand_base: {
  new (
    input: CreateModelInvocationJobCommandInput
  ): import("@smithy/core/client").CommandImpl<
    CreateModelInvocationJobCommandInput,
    CreateModelInvocationJobCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: CreateModelInvocationJobCommandInput
  ): import("@smithy/core/client").CommandImpl<
    CreateModelInvocationJobCommandInput,
    CreateModelInvocationJobCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class CreateModelInvocationJobCommand extends CreateModelInvocationJobCommand_base {
  protected static __types: {
    api: {
      input: CreateModelInvocationJobRequest;
      output: CreateModelInvocationJobResponse;
    };
    sdk: {
      input: CreateModelInvocationJobCommandInput;
      output: CreateModelInvocationJobCommandOutput;
    };
  };
}
