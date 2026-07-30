import type { Command } from '../../../commands.js';
import { CommunityDialog } from './CommunityDialog.js';

const community: Command = {
  type: 'local-jsx',
  name: 'raphael community',
  aliases: ['rc', 'community'],
  description: 'Multi-model collaborative problem solving (WORMGPT, Kimi, Mistral, Gemma)',
  argumentHint: '<question>',
  load: () => import('./CommunityDialog.js'),
};

export default community;