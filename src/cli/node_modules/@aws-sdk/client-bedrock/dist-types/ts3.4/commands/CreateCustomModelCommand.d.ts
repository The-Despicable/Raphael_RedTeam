import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  CreateCustomModelRequest,
  CreateCustomModelResponse,
} from "../models/models_0";
export { __MetadataBearer };
export { $Command };
export interface CreateCustomModelCommandInput
  extends CreateCustomModelRequest {}
export interface CreateCustomModelCommandOutput
  extends CreateCustomModelResponse,
    __MetadataBearer {}
declare const CreateCustomModelCommand_base: {
  new (
    input: CreateCustomModelCommandInput
  ): import("@smithy/core/client").CommandImpl<
    CreateCustomModelCommandInput,
    CreateCustomModelCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: CreateCustomModelCommandInput
  ): import("@smithy/core/client").CommandImpl<
    CreateCustomModelCommandInput,
    CreateCustomModelCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class CreateCustomModelCommand extends CreateCustomModelCommand_base {
  protected static __types: {
    api: {
      input: CreateCustomModelRequest;
      output: CreateCustomModelResponse;
    };
    sdk: {
      input: CreateCustomModelCommandInput;
      output: CreateCustomModelCommandOutput;
    };
  };
}
