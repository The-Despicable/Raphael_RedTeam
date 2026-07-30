import type { Command } from '../../../commands.js';
import { KaliDialog } from './KaliDialog.js';

const kali: Command = {
  type: 'local-jsx',
  name: 'raphael kali',
  aliases: ['rk', 'kali'],
  description: 'Kali Linux tools (300+ tools via local or remote execution)',
  argumentHint: '<tool> [args]',
  load: () => import('./KaliDialog.js'),
};

export default kali;