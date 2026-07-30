import { Paginator } from "@smithy/types";
import {
  ListAdvancedPromptOptimizationJobsCommandInput,
  ListAdvancedPromptOptimizationJobsCommandOutput,
} from "../commands/ListAdvancedPromptOptimizationJobsCommand";
import { BedrockPaginationConfiguration } from "./Interfaces";
export declare const paginateListAdvancedPromptOptimizationJobs: (
  config: BedrockPaginationConfiguration,
  input: ListAdvancedPromptOptimizationJobsCommandInput,
  ...rest: any[]
) => Paginator<ListAdvancedPromptOptimizationJobsCommandOutput>;
