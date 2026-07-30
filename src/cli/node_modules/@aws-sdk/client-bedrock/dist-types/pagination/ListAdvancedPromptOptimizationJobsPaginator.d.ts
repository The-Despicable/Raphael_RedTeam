import type { Paginator } from "@smithy/types";
import { ListAdvancedPromptOptimizationJobsCommandInput, ListAdvancedPromptOptimizationJobsCommandOutput } from "../commands/ListAdvancedPromptOptimizationJobsCommand";
import type { BedrockPaginationConfiguration } from "./Interfaces";
/**
 * @public
 */
export declare const paginateListAdvancedPromptOptimizationJobs: (config: BedrockPaginationConfiguration, input: ListAdvancedPromptOptimizationJobsCommandInput, ...rest: any[]) => Paginator<ListAdvancedPromptOptimizationJobsCommandOutput>;
