import type { Command } from '../../../commands.js';
import { DeepResearchDialog } from './DeepResearchDialog.js';

const deepResearch: Command = {
  type: 'local-jsx',
  name: 'raphael deep-research',
  aliases: ['rdr', 'deepresearch'],
  description: 'Deep research with phased methodology and adversarial verification',
  argumentHint: '<topic>',
  load: () => import('./DeepResearchDialog.js'),
};

export default deepResearch;