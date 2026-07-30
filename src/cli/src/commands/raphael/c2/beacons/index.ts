import type { Command } from '../../../../../commands.js';
import { BeaconsDialog } from './BeaconsDialog.js';

const beacons: Command = {
  type: 'local-jsx',
  name: 'beacons',
  description: 'List and manage active C2 beacons',
  argumentHint: '[beacon_id] [task_json]',
  load: () => import('./BeaconsDialog.js'),
};

export default beacons;