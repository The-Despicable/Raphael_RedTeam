import { Command as $Command } from "@smithy/core/client";
import { MetadataBearer as __MetadataBearer } from "@smithy/types";
import {
  AssumeRoleWithSAMLRequest,
  AssumeRoleWithSAMLResponse,
} from "../models/models_0";
import {
  ServiceInputTypes,
  ServiceOutputTypes,
  STSClientResolvedConfig,
} from "../STSClient";
export { __MetadataBearer };
export { $Command };
export interface AssumeRoleWithSAMLCommandInput
  extends AssumeRoleWithSAMLRequest {}
export interface AssumeRoleWithSAMLCommandOutput
  extends AssumeRoleWithSAMLResponse,
    __MetadataBearer {}
declare const AssumeRoleWithSAMLCommand_base: {
  new (
    input: AssumeRoleWithSAMLCommandInput
  ): import("@smithy/core/client").CommandImpl<
    AssumeRoleWithSAMLCommandInput,
    AssumeRoleWithSAMLCommandOutput,
    STSClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  new (
    input: AssumeRoleWithSAMLCommandInput
  ): import("@smithy/core/client").CommandImpl<
    AssumeRoleWithSAMLCommandInput,
    AssumeRoleWithSAMLCommandOutput,
    STSClientResolvedConfig,
    ServiceInputTypes,
    ServiceOutputTypes
  >;
  getEndpointParameterInstructions(): {
    [x: string]: unknown;
  };
};
export declare class AssumeRoleWithSAMLCommand extends AssumeRoleWithSAMLCommand_base {
  protected static __types: {
    api: {
      input: AssumeRoleWithSAMLRequest;
      output: AssumeRoleWithSAMLResponse;
    };
    sdk: {
      input: AssumeRoleWithSAMLCommandInput;
      output: AssumeRoleWithSAMLCommandOutput;
    };
  };
}
