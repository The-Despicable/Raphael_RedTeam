import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  BatchDeleteEvaluationJobRequest,
  BatchDeleteEvaluationJobResponse,
} from "../models/models_0";
export { __MetadataBearer };
export { $Command };
export interface BatchDeleteEvaluationJobCommandInput
  extends BatchDeleteEvaluationJobRequest {}
export interface BatchDeleteEvaluationJobCommandOutput
  extends BatchDeleteEvaluationJobResponse,
    __MetadataBearer {}
declare const BatchDeleteEvaluationJobCommand_base: {
  new (
    input: BatchDeleteEvaluationJobCommandInput
  ): import("@smithy/core/client").CommandImpl<
    BatchDeleteEvaluationJobCommandInput,
    BatchDeleteEvaluationJobCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: BatchDeleteEvaluationJobCommandInput
  ): import("@smithy/core/client").CommandImpl<
    BatchDeleteEvaluationJobCommandInput,
    BatchDeleteEvaluationJobCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class BatchDeleteEvaluationJobCommand extends BatchDeleteEvaluationJobCommand_base {
  protected static __types: {
    api: {
      input: BatchDeleteEvaluationJobRequest;
      output: BatchDeleteEvaluationJobResponse;
    };
    sdk: {
      input: BatchDeleteEvaluationJobCommandInput;
      output: BatchDeleteEvaluationJobCommandOutput;
    };
  };
}
