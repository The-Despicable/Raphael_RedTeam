import type { Command } from '../../../../../commands.js';
import { SliverDialog } from './index.js';

const sliver: Command = {
  type: 'local-jsx',
  name: 'sliver',
  description: 'Sliver C2 framework integration',
  argumentHint: '<subcommand>',
  load: () => import('./index.js'),
};

export default sliver;