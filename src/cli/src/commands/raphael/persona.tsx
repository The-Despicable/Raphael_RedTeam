import * as React from 'react'
import { useAppState, useSetAppState } from '../../state/AppState.js'
import { DialogSelect } from '../../ui/dialog-select'
import { useDialog } from '../../ui/dialog'
import { raphaelPersonas } from '../../constants/prompts.js'

const RAPHAEL_PERSONAS = [
  { id: 'stealth', title: 'Stealth', description: 'Low and slow — avoid detection' },
  { id: 'aggressive', title: 'Aggressive', description: 'Fast and loud — maximise speed' },
  { id: 'z3r0', title: 'Z3R0', description: 'Ghost in the network — cold, minimal, no sentiment' },
] as const

export function PersonaDialog() {
  const appState = useAppState()
  const setAppState = useSetAppState()
  const dialog = useDialog()

  const options = [
    { value: 'stealth', title: 'Stealth', description: 'Low and slow — avoid detection' },
    { value: 'aggressive', title: 'Aggressive', description: 'Fast and loud — maximise speed' },
    { value: 'z3r0', title: 'Z3R0', description: 'Ghost in the network — cold, minimal, no sentiment' },
  ]

  return (
    <DialogSelect
      title="Raphael persona"
      current={appState.raphaelPersona}
      options={options}
      onSelect={(option) => {
        setAppState((prev) => ({ ...prev, raphaelPersona: option.value }))
        console.log(`[Raphael] Persona set to ${option.value}`)
        dialog.clear()
      }}
    />
  )
}

export function PersonaCommand(args: string) {
  const setAppState = useSetAppState()
  const persona = args.trim().toLowerCase()
  if (!['stealth', 'aggressive', 'z3r0'].includes(persona)) {
    return 'Invalid persona. Available: stealth, aggressive, z3r0'
  }
  setAppState((prev: any) => ({ ...prev, raphaelPersona: persona }))
  return `Persona set to ${persona}`
}