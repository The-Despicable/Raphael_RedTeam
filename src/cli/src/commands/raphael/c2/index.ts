import type { Command } from '../../../commands.js';

const c2: Command = {
  type: 'local',
  name: 'raphael c2',
  description: 'C2 framework management (build, deploy, beacons, Sliver)',
  subcommands: [
    await import('./build/index.js'),
    await import('./deploy/index.js'),
    await import('./beacons/index.js'),
    await import('./sliver/index.js'),
  ],
};

export default c2;