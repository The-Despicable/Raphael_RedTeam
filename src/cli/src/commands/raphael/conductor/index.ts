import type { Command } from '../../../commands.js';
import { ConductorDialog } from './ConductorDialog.js';

const conductor: Command = {
  type: 'local-jsx',
  name: 'raphael conductor',
  aliases: ['rc', 'conduct'],
  description: 'Safety-filtered model routing and RL strategy selection',
  load: () => import('./ConductorDialog.js'),
};

export default conductor;