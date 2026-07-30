import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  RegisterMarketplaceModelEndpointRequest,
  RegisterMarketplaceModelEndpointResponse,
} from "../models/models_0";
export { __MetadataBearer };
export { $Command };
export interface RegisterMarketplaceModelEndpointCommandInput
  extends RegisterMarketplaceModelEndpointRequest {}
export interface RegisterMarketplaceModelEndpointCommandOutput
  extends RegisterMarketplaceModelEndpointResponse,
    __MetadataBearer {}
declare const RegisterMarketplaceModelEndpointCommand_base: {
  new (
    input: RegisterMarketplaceModelEndpointCommandInput
  ): import("@smithy/core/client").CommandImpl<
    RegisterMarketplaceModelEndpointCommandInput,
    RegisterMarketplaceModelEndpointCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: RegisterMarketplaceModelEndpointCommandInput
  ): import("@smithy/core/client").CommandImpl<
    RegisterMarketplaceModelEndpointCommandInput,
    RegisterMarketplaceModelEndpointCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class RegisterMarketplaceModelEndpointCommand extends RegisterMarketplaceModelEndpointCommand_base {
  protected static __types: {
    api: {
      input: RegisterMarketplaceModelEndpointRequest;
      output: RegisterMarketplaceModelEndpointResponse;
    };
    sdk: {
      input: RegisterMarketplaceModelEndpointCommandInput;
      output: RegisterMarketplaceModelEndpointCommandOutput;
    };
  };
}
