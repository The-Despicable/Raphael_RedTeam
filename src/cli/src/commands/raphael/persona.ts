import type { Command } from '../../commands.js'

const RAPHAEL_PERSONAS = ['stealth', 'aggressive', 'z3r0'] as const

export default {
  type: 'local',
  name: 'persona',
  description: 'Set Raphael persona (stealth|aggressive|z3r0)',
  argumentHint: '<persona>',
  handler: (args: string) => {
    const persona = args.trim().toLowerCase()
    if (!['stealth', 'aggressive', 'z3r0'].includes(persona)) {
      return 'Invalid persona. Available: stealth, aggressive, z3r0'
    }
    return `Persona set to ${persona}. Use /persona to open dialog.`
  },
} satisfies Command