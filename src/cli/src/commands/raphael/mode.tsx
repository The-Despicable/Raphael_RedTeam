import * as React from 'react'
import { useAppState, useSetAppState } from '../../state/AppState.js'
import { DialogSelect } from '../../ui/dialog-select'
import { useDialog } from '../../ui/dialog'
import { createMemo } from 'solid-js'
import { raphaelModes } from '../../constants/prompts.js'
import { logForDebugging } from '../../utils/debug.js'

const RAPHAEL_MODES = [
  { id: 'autonomous', title: 'Autonomous', description: 'Full autonomous attack — scan, exploit, pivot, exfil' },
  { id: 'recon', title: 'Recon', description: 'Passive reconnaissance only — no exploitation' },
  { id: 'community', title: 'Community', description: 'Community-driven threat intelligence and collaboration' },
  { id: 'debate', title: 'Debate', description: 'Multi-model debate for consensus-driven analysis' },
  { id: 'rsi', title: 'RSI', description: 'Raphael Security Intelligence — advanced threat correlation' },
  { id: 'persona', title: 'Persona', description: 'Persona-based OPSEC configuration' },
] as const

export function ModeDialog() {
  const appState = useAppState()
  const setAppState = useSetAppState()
  const dialog = useDialog()

  const options = createMemo(() =>
    RAPHAEL_MODES.map((mode) => ({
      value: mode.id,
      title: mode.title,
      description: mode.description,
    })),
  )

  return (
    <DialogSelect
      title="Raphael mode"
      current={appState.raphaelMode}
      options={options()}
      onSelect={(option) => {
        setAppState((prev) => ({ ...prev, raphaelMode: option.value }))
        logForDebugging(`[Raphael] Mode set to ${option.value}`)
        dialog.clear()
      }}
    />
  )
}

export function ModeCommand(args: string) {
  const setAppState = useSetAppState()
  const mode = args.trim().toLowerCase()
  if (!['autonomous', 'recon', 'community', 'debate', 'rsi', 'persona'].includes(mode)) {
    return 'Invalid mode. Available: autonomous, recon, community, debate, rsi, persona'
  }
  setAppState((prev: any) => ({ ...prev, raphaelMode: mode }))
  logForDebugging(`[Raphael] Mode set to ${mode}`)
  return `Mode set to ${mode}`
}