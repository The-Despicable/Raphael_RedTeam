import type { Command } from '../../commands.js'
import { logForDebugging } from '../../utils/debug.js'

const RAPHAEL_MODES = [
  'autonomous',
  'recon',
  'community',
  'debate',
  'rsi',
  'persona',
] as const

export default {
  type: 'local',
  name: 'mode',
  description: 'Set Raphael operation mode',
  argumentHint: '<mode>',
  aliases: ['autonomous', 'recon', 'community', 'debate', 'rsi'],
  handler: (args: string) => {
    const mode = args.trim().toLowerCase()
    if (!RAPHAEL_MODES.includes(mode as any)) {
      return `Invalid mode. Available: ${RAPHAEL_MODES.join(', ')}`
    }
    // The state will be set by the context
    logForDebugging(`[Raphael] Mode command: ${mode}`)
    return `Mode set to ${mode}. Use /mode to open dialog.`
  },
} satisfies Command