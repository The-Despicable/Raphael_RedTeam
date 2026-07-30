import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  StopModelCustomizationJobRequest,
  StopModelCustomizationJobResponse,
} from "../models/models_1";
export { __MetadataBearer };
export { $Command };
export interface StopModelCustomizationJobCommandInput
  extends StopModelCustomizationJobRequest {}
export interface StopModelCustomizationJobCommandOutput
  extends StopModelCustomizationJobResponse,
    __MetadataBearer {}
declare const StopModelCustomizationJobCommand_base: {
  new (
    input: StopModelCustomizationJobCommandInput
  ): import("@smithy/core/client").CommandImpl<
    StopModelCustomizationJobCommandInput,
    StopModelCustomizationJobCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: StopModelCustomizationJobCommandInput
  ): import("@smithy/core/client").CommandImpl<
    StopModelCustomizationJobCommandInput,
    StopModelCustomizationJobCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class StopModelCustomizationJobCommand extends StopModelCustomizationJobCommand_base {
  protected static __types: {
    api: {
      input: StopModelCustomizationJobRequest;
      output: {};
    };
    sdk: {
      input: StopModelCustomizationJobCommandInput;
      output: StopModelCustomizationJobCommandOutput;
    };
  };
}
