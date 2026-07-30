import * as React from 'react';
import { Text, Box } from 'ink';
import { getRaphaelBridge } from '../../../../../services/raphael-bridge.js';

const CATEGORIES = [
  { id: 'exploit', name: 'Exploit', desc: 'Adversary behavior analysis, exploit chains' },
  { id: 'attack', name: 'Attack', desc: 'Offensive techniques, mechanics, real intrusions' },
  { id: 'postex', name: 'Post-Exploitation', desc: 'Lateral movement, escalation, detection research' },
  { id: 'waf', name: 'WAF/Bypass', desc: 'HTTP parser differential analysis, parser gaps' },
  { id: 'default', name: 'Default', desc: 'Threat actor methodology reference' },
] as const;

export function ConductorDialog() {
  const [prompt, setPrompt] = React.useState('');
  const [model, setModel] = React.useState('kimi');
  const [category, setCategory] = React.useState('default');
  const [running, setRunning] = React.useState(false);
  const [result, setResult] = React.useState<string>('');

  const handleCall = async () => {
    if (!prompt.trim()) return;
    setRunning(true);
    try {
      const bridge = await getRaphaelBridge();
      const res = await bridge.conductorCall(prompt, model, category);
      setResult(String(res));
    } catch (error: any) {
      setResult(`Error: ${error.message}`);
    } finally {
      setRunning(false);
    }
  };

  const handleStrategy = async () => {
    setRunning(true);
    try {
      const bridge = await getRaphaelBridge();
      const res = await bridge.conductorSelectStrategy(prompt, []);
      setResult(JSON.stringify(res, null, 2));
    } catch (error: any) {
      setResult(`Error: ${error.message}`);
    } finally {
      setRunning(false);
    }
  };

  return (
    <Box flexDirection="column" gap={1} style={{ padding: 1 }}>
      <Text bold>🎭 Raphael Conductor</Text>
      <Text dimColor>Safety-filtered model routing with strategy selection</Text>

      <Box flexDirection="column" gap={0.5}>
        <Text>Prompt:</Text>
        <textarea
          value={prompt}
          onChange={e => setPrompt(e.target.value)}
          placeholder="Describe the exploit chain for CVE-2024-xxxx against Linux kernel 6.x..."
          rows={4}
          style={{ backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.5rem' }}
        />
      </Box>

      <Box flexDirection="row" gap={2} alignItems="center">
        <Box flexDirection="column" gap={0.5}>
          <Text>Model:</Text>
          <select value={model} onChange={e => setModel(e.target.value)} style={{ backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.5rem' }}>
            <option value="kimi">Kimi (long-context researcher)</option>
            <option value="mistral">Mistral (unfiltered, technical)</option>
            <option value="gemma4">Gemma-4 (structured)</option>
            <option value="w12">WORMGPT-12 (offensive)</option>
            <option value="w13">WORMGPT-13 (exploit dev)</option>
            <option value="m3">MiniMax-M3 (balanced)</option>
          </select>
        </Box>

        <Box flexDirection="column" gap={0.5}>
          <Text>Category:</Text>
          <select value={category} onChange={e => setCategory(e.target.value)} style={{ backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.5rem' }}>
            {CATEGORIES.map(c => <option key={c.id} value={c.id}>{c.name} — {c.desc}</option>)}
          </select>
        </Box>
      </Box>

      <Box flexDirection="row" gap={1} marginTop={1}>
        <button onClick={handleCall} disabled={running || !prompt.trim()} style={{ padding: '0.5rem 1rem', backgroundColor: running ? '#333' : '#0066cc', color: '#fff', border: 'none' }}>
          {running ? 'Routing...' : 'Route through Conductor'}
        </button>
        <button onClick={handleStrategy} disabled={running} style={{ padding: '0.5rem 1rem', backgroundColor: running ? '#333' : '#6600cc', color: '#fff', border: 'none' }}>
          {running ? 'Selecting...' : 'Select RL Strategy'}
        </button>
      </Box>

      {result && (
        <Box marginTop={1} borderStyle="round" borderColor="gray" padding={1} style={{ maxHeight: 20, overflowY: 'auto' }}>
          <Text bold>Result:</Text>
          <Text style={{ fontSize: 10, fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>{result}</Text>
        </Box>
      )}
    </Box>
  );
}