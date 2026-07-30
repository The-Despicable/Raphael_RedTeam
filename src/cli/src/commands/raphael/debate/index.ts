import type { Command } from '../../../commands.js';
import { DebateDialog } from './DebateDialog.js';

const debate: Command = {
  type: 'local-jsx',
  name: 'raphael debate',
  description: 'Adversarial debate between two models with skill evidence',
  argumentHint: '<question> [options]',
  load: () => import('./DebateDialog.js'),
};

export default debate;