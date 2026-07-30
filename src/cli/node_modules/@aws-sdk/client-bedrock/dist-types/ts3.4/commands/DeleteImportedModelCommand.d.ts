import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  DeleteImportedModelRequest,
  DeleteImportedModelResponse,
} from "../models/models_1";
export { __MetadataBearer };
export { $Command };
export interface DeleteImportedModelCommandInput
  extends DeleteImportedModelRequest {}
export interface DeleteImportedModelCommandOutput
  extends DeleteImportedModelResponse,
    __MetadataBearer {}
declare const DeleteImportedModelCommand_base: {
  new (
    input: DeleteImportedModelCommandInput
  ): import("@smithy/core/client").CommandImpl<
    DeleteImportedModelCommandInput,
    DeleteImportedModelCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: DeleteImportedModelCommandInput
  ): import("@smithy/core/client").CommandImpl<
    DeleteImportedModelCommandInput,
    DeleteImportedModelCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class DeleteImportedModelCommand extends DeleteImportedModelCommand_base {
  protected static __types: {
    api: {
      input: DeleteImportedModelRequest;
      output: {};
    };
    sdk: {
      input: DeleteImportedModelCommandInput;
      output: DeleteImportedModelCommandOutput;
    };
  };
}
