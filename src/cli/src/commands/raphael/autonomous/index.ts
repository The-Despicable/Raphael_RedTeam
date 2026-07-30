import type { Command } from '../../commands.js';
import { AutonomousDialog } from './AutonomousDialog.js';

const autonomous: Command = {
  type: 'local-jsx',
  name: 'raphael autonomous',
  aliases: ['ra', 'auto'],
  description: 'Launch full autonomous operation against a target',
  argumentHint: '<target> [options]',
  load: () => import('./AutonomousDialog.js'),
};

export default autonomous;