import type { Command } from '../../../commands.js';
import { BrainDialog } from './BrainDialog.js';

const brain: Command = {
  type: 'local-jsx',
  name: 'raphael brain',
  aliases: ['rb', 'brain'],
  description: 'Neural memory, analytics, and adaptive strategy',
  load: () => import('./BrainDialog.js'),
};

export default brain;