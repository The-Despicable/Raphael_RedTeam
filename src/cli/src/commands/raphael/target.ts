import type { Command } from '../../commands.js'

export default {
  type: 'local',
  name: 'target',
  description: 'Set the target IP, domain, or CIDR for Raphael operations',
  argumentHint: '<target>',
  load: () => import('./target.js'),
} satisfies Command