import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  BedrockClientResolvedConfig,
  ServiceInputTypes,
  ServiceOutputTypes,
} from "../BedrockClient";
import {
  DeregisterMarketplaceModelEndpointRequest,
  DeregisterMarketplaceModelEndpointResponse,
} from "../models/models_0";
export { __MetadataBearer };
export { $Command };
export interface DeregisterMarketplaceModelEndpointCommandInput
  extends DeregisterMarketplaceModelEndpointRequest {}
export interface DeregisterMarketplaceModelEndpointCommandOutput
  extends DeregisterMarketplaceModelEndpointResponse,
    __MetadataBearer {}
declare const DeregisterMarketplaceModelEndpointCommand_base: {
  new (
    input: DeregisterMarketplaceModelEndpointCommandInput
  ): import("@smithy/core/client").CommandImpl<
    DeregisterMarketplaceModelEndpointCommandInput,
    DeregisterMarketplaceModelEndpointCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: DeregisterMarketplaceModelEndpointCommandInput
  ): import("@smithy/core/client").CommandImpl<
    DeregisterMarketplaceModelEndpointCommandInput,
    DeregisterMarketplaceModelEndpointCommandOutput,
    BedrockClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class DeregisterMarketplaceModelEndpointCommand extends DeregisterMarketplaceModelEndpointCommand_base {
  protected static __types: {
    api: {
      input: DeregisterMarketplaceModelEndpointRequest;
      output: {};
    };
    sdk: {
      input: DeregisterMarketplaceModelEndpointCommandInput;
      output: DeregisterMarketplaceModelEndpointCommandOutput;
    };
  };
}
