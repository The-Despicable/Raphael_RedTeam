import type { Command } from '../../../../../commands.js';
import { BuildImplantDialog } from './BuildImplantDialog.js';

const build: Command = {
  type: 'local-jsx',
  name: 'build',
  description: 'Build a C2 implant (native, Sliver, or noop)',
  argumentHint: '[options]',
  load: () => import('./BuildImplantDialog.js'),
};

export default build;