import type { Command } from '../../../../../commands.js';
import { DeployImplantDialog } from './DeployImplantDialog.js';

const deploy: Command = {
  type: 'local-jsx',
  name: 'deploy',
  description: 'Deploy implant to target',
  argumentHint: '<implant_path> <target> [options]',
  load: () => import('./DeployImplantDialog.js'),
};

export default deploy;