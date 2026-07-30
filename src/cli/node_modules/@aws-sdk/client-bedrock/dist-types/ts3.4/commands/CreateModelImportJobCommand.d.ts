import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  CreateModelImportJobRequest,
  CreateModelImportJobResponse,
} from "../models/models_1";
export { __MetadataBearer };
export { $Command };
export interface CreateModelImportJobCommandInput
  extends CreateModelImportJobRequest {}
export interface CreateModelImportJobCommandOutput
  extends CreateModelImportJobResponse,
    __MetadataBearer {}
declare const CreateModelImportJobCommand_base: {
  new (
    input: CreateModelImportJobCommandInput
  ): import("@smithy/core/client").CommandImpl<
    CreateModelImportJobCommandInput,
    CreateModelImportJobCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: CreateModelImportJobCommandInput
  ): import("@smithy/core/client").CommandImpl<
    CreateModelImportJobCommandInput,
    CreateModelImportJobCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class CreateModelImportJobCommand extends CreateModelImportJobCommand_base {
  protected static __types: {
    api: {
      input: CreateModelImportJobRequest;
      output: CreateModelImportJobResponse;
    };
    sdk: {
      input: CreateModelImportJobCommandInput;
      output: CreateModelImportJobCommandOutput;
    };
  };
}
