import type { Command } from '../../../commands.js';
import { HarvesterDialog } from './HarvesterDialog.js';

const harvester: Command = {
  type: 'local-jsx',
  name: 'raphael harvester',
  aliases: ['rh', 'harvest'],
  description: 'Threat intelligence harvester (CVEs, GitHub PoCs, ATT&CK techniques)',
  load: () => import('./HarvesterDialog.js'),
};

export default harvester;