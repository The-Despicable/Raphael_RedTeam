import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  GetAccessKeyInfoRequest,
  GetAccessKeyInfoResponse,
} from "../models/models_0";
import {
  ServiceInputTypes,
  ServiceOutputTypes,
  STSClientResolvedConfig,
} from "../STSClient";
export { __MetadataBearer };
export { $Command };
export interface GetAccessKeyInfoCommandInput extends GetAccessKeyInfoRequest {}
export interface GetAccessKeyInfoCommandOutput
  extends GetAccessKeyInfoResponse,
    __MetadataBearer {}
declare const GetAccessKeyInfoCommand_base: {
  new (
    input: GetAccessKeyInfoCommandInput
  ): import("@smithy/core/client").CommandImpl<
    GetAccessKeyInfoCommandInput,
    GetAccessKeyInfoCommandOutput,
    STSClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: GetAccessKeyInfoCommandInput
  ): import("@smithy/core/client").CommandImpl<
    GetAccessKeyInfoCommandInput,
    GetAccessKeyInfoCommandOutput,
    STSClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class GetAccessKeyInfoCommand extends GetAccessKeyInfoCommand_base {
  protected static __types: {
    api: {
      input: GetAccessKeyInfoRequest;
      output: GetAccessKeyInfoResponse;
    };
    sdk: {
      input: GetAccessKeyInfoCommandInput;
      output: GetAccessKeyInfoCommandOutput;
    };
  };
}
