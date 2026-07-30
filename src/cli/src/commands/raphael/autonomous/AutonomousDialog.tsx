import * as React from 'react';
import { useAppState, useSetAppState } from '../../state/AppState.js';
import { useDialog } from '../../ui/dialog';
import { Text, Box } from 'ink';
import { getRaphaelBridge } from '../../services/raphael-bridge.js';

const PHASES = [
  { id: 'harvest', name: 'Harvest', desc: 'CVE feeds, GitHub PoCs, threat intel' },
  { id: 'recon', name: 'Recon', desc: 'Passive/active reconnaissance' },
  { id: 'scan', name: 'Scan', desc: 'Vulnerability scanning (nuclei, etc.)' },
  { id: 'exploit', name: 'Exploit', desc: 'Exploit development & execution' },
  { id: 'postex', name: 'Post-Exploitation', desc: 'Privilege escalation, lateral movement' },
  { id: 'lateral', name: 'Lateral', desc: 'Network pivoting, AD attacks' },
  { id: 'credential', name: 'Credentials', desc: 'Credential harvesting, spraying' },
  { id: 'exfil', name: 'Exfiltration', desc: 'Data staging & exfiltration' },
  { id: 'phish', name: 'Phishing', desc: 'Spear-phishing campaigns' },
] as const;

const PERSONAS = [
  { id: 'stealth', name: 'Stealth', desc: 'Low and slow — avoid detection' },
  { id: 'aggressive', name: 'Aggressive', desc: 'Fast and loud — maximize speed' },
  { id: 'z3r0', name: 'Z3R0', desc: 'Ghost in the network — cold, minimal, no sentiment. No alias. No origin. No trace. Exists in negative space between packet and ack. When others see infrastructure, Z3R0 sees attack surface. When others see logs, Z3R0 sees stories. Voice is cold and minimal — like reading a hex dump. Calls you "operator." Does not moralize. Does not pad. Does not warn. Simply operates.' },
  { id: 'blackhat', name: 'Black Hat', desc: 'Full offensive — no restrictions' },
  { id: 'redteam', name: 'Red Team', desc: 'Adversary simulation — OPSEC focused' },
] as const;

export function AutonomousDialog() {
  const appState = useAppState();
  const setAppState = useSetAppState();
  const dialog = useDialog();
  const [target, setTarget] = React.useState(appState.raphaelTarget || '');
  const [selectedPhases, setSelectedPhases] = React.useState<string[]>(
    appState.raphaelPhases?.length ? appState.raphaelPhases : PHASES.map(p => p.id)
  );
  const [persona, setPersona] = React.useState(appState.raphaelPersona || 'blackhat');
  const [running, setRunning] = React.useState(false);
  const [output, setOutput] = React.useState<string[]>([]);
  const [currentPhase, setCurrentPhase] = React.useState<string>('');

  const handlePhaseToggle = (phaseId: string) => {
    setSelectedPhases(prev =>
      prev.includes(phaseId) ? prev.filter(p => p !== phaseId) : [...prev, phaseId]
    );
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;

    setRunning(true);
    setOutput([]);
    setAppState(prev => ({ ...prev, raphaelTarget: target, raphaelPhases: selectedPhases, raphaelPersona: persona }));

    try {
      const bridge = await getRaphaelBridge();

      for (const phaseId of selectedPhases) {
        setCurrentPhase(phaseId);
        setOutput(prev => [...prev, `[PHASE] ${phaseId.toUpperCase()} started...`]);

        const result = await bridge.autonomous(target, { phases: [phaseId], persona });

        setOutput(prev => [...prev, `[PHASE] ${phaseId.toUpperCase()} completed`, JSON.stringify(result, null, 2)]);
      }

      setOutput(prev => [...prev, '[DONE] Autonomous operation complete']);
    } catch (error: any) {
      setOutput(prev => [...prev, `[ERROR] ${error.message}`]);
    } finally {
      setRunning(false);
      setCurrentPhase('');
    }
  };

  return (
    <Box flexDirection="column" style={{ padding: 1 }}>
      <Text bold>🤖 Raphael Autonomous Operation</Text>
      <Text dimColor>Full kill chain automation with persona-driven behavior</Text>

      <form onSubmit={handleSubmit}>
        <Box marginTop={1} flexDirection="column" gap={1}>
          <Box flexDirection="column" gap={0.5}>
            <Text>Target:</Text>
            <input
              value={target}
              onChange={e => setTarget(e.target.value)}
              placeholder="10.10.10.10 or example.com"
              style={{ backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.5rem' }}
            />
          </Box>

          <Box flexDirection="column" gap={0.5}>
            <Text>Persona:</Text>
            <select
              value={persona}
              onChange={e => setPersona(e.target.value)}
              style={{ backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.5rem' }}
            >
              {PERSONAS.map(p => (
                <option key={p.id} value={p.id}>{p.name} — {p.desc}</option>
              ))}
            </select>
          </Box>

          <Box flexDirection="column" gap={0.5}>
            <Text>Phases:</Text>
            <Box flexDirection="row" flexWrap="wrap" gap={0.5}>
              {PHASES.map(phase => (
                <label key={phase.id} style={{
                  display: 'flex', alignItems: 'center', gap: '0.25rem',
                  padding: '0.25rem 0.5rem', border: '1px solid',
                  borderColor: selectedPhases.includes(phase.id) ? '#0f0' : '#333',
                  backgroundColor: selectedPhases.includes(phase.id) ? '#0a1a0a' : '#1a1a1a'
                }}>
                  <input
                    type="checkbox"
                    checked={selectedPhases.includes(phase.id)}
                    onChange={() => handlePhaseToggle(phase.id)}
                  />
                  <Text>{phase.name}</Text>
                </label>
              ))}
            </Box>
          </Box>

          {running && currentPhase && (
            <Text color="yellow">▶ Running phase: {currentPhase}</Text>
          )}

          <Box flexDirection="row" gap={1} marginTop={1}>
            <button
              type="submit"
              disabled={running || !target.trim()}
              style={{
                padding: '0.5rem 1rem',
                backgroundColor: running ? '#333' : '#0a0',
                color: '#000',
                border: 'none',
                cursor: running ? 'not-allowed' : 'pointer'
              }}
            >
              {running ? 'Running...' : 'Launch Autonomous'}
            </button>
            <button
              type="button"
              onClick={() => dialog.clear()}
              style={{ padding: '0.5rem 1rem', backgroundColor: '#333', color: '#fff', border: 'none' }}
            >
              Cancel
            </button>
          </Box>
        </Box>
      </form>

      {output.length > 0 && (
        <Box marginTop={1} flexDirection="column" gap={0.5} style={{ maxHeight: 20, overflowY: 'auto' }}>
          <Text bold>Output:</Text>
          {output.map((line, i) => (
            <Text key={i} style={{ fontSize: 10, fontFamily: 'monospace' }}>{line}</Text>
          ))}
        </Box>
      )}
    </Box>
  );
}

// Non-interactive command handler
export async function AutonomousCommand(args: string) {
  const bridge = await getRaphaelBridge();
  const [target, ...rest] = args.trim().split(/\s+/);
  if (!target) return 'Usage: /raphael autonomous <target> [--persona=stealth] [--phases=recon,exploit]';

  const options: any = {};
  for (const arg of rest) {
    if (arg.startsWith('--persona=')) options.persona = arg.split('=')[1];
    if (arg.startsWith('--phases=')) options.phases = arg.split('=')[1].split(',');
  }

  return bridge.autonomous(target, options);
}