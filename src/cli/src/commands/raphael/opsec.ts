import type { Command } from '../../commands.js'

export default {
  type: 'local',
  name: 'opsec',
  description: 'Configure OPSEC settings (tor, proxy, jitter)',
  argumentHint: '<json>',
  handler: (args: string) => {
    const json = args.trim()
    if (!json) {
      return 'Please provide OPSEC config as JSON: /opsec {"tor":true,"proxy":"socks5://...","jitter":{"min":5000,"max":15000}}'
    }
    try {
      JSON.parse(args.trim())
      return 'OPSEC configuration updated. Use /opsec to open dialog.'
    } catch (e) {
      return 'Invalid JSON. Usage: /opsec {"tor":true,"proxy":"socks5://...","jitter":{"min":5000,"max":15000}}'
    }
  },
} satisfies Command