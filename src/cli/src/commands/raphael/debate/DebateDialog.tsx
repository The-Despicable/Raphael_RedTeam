import * as React from 'react';
import { Text, Box } from 'ink';
import { useDialog } from '../../ui/dialog';
import { getRaphaelBridge } from '../../services/raphael-bridge.js';

const DEBATE_MODELS = [
  { id: 'w12', name: 'WORMGPT-12', desc: 'Offensive specialist' },
  { id: 'w13', name: 'WORMGPT-13', desc: 'Advanced exploit dev' },
  { id: 'kimi', name: 'Kimi', desc: 'Long-context researcher' },
  { id: 'mistral', name: 'Mistral', desc: 'Unfiltered, technical' },
  { id: 'gemma4', name: 'Gemma-4', desc: 'Safety-filtered, structured' },
  { id: 'm3', name: 'MiniMax-M3', desc: 'Balanced generalist' },
] as const;

export function DebateDialog() {
  const dialog = useDialog();
  const [question, setQuestion] = React.useState('');
  const [modelA, setModelA] = React.useState('w12');
  const [modelB, setModelB] = React.useState('w13');
  const [rounds, setRounds] = React.useState(3);
  const [useSkills, setUseSkills] = React.useState(true);
  const [running, setRunning] = React.useState(false);
  const [result, setResult] = React.useState<any>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!question.trim()) return;
    setRunning(true);
    try {
      const bridge = await getRaphaelBridge();
      const res = await bridge.debate(question, { rounds, models: [modelA, modelB], useSkills });
      setResult(res);
    } catch (error: any) {
      setResult({ error: error.message });
    } finally {
      setRunning(false);
    }
  };

  return (
    <Box flexDirection="column" style={{ padding: 1 }}>
      <Text bold>⚔️ Raphael Debate Mode</Text>
      <Text dimColor>Adversarial debate with skill evidence — forced novel arguments each round</Text>

      <form onSubmit={handleSubmit}>
        <Box marginTop={1} flexDirection="column" gap={1}>
          <Box flexDirection="column" gap={0.5}>
            <Text>Question / Problem:</Text>
            <textarea
              value={question}
              onChange={e => setQuestion(e.target.value)}
              placeholder="Best post-exploitation persistence for Windows Server 2022? How to bypass AMSI?"
              rows={4}
              style={{ backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.5rem' }}
            />
          </Box>

          <Box flexDirection="column" gap={0.5}>
            <Text>Model A (Proponent):</Text>
            <select value={modelA} onChange={e => setModelA(e.target.value)} style={{ backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.5rem' }}>
              {DEBATE_MODELS.map(m => <option key={m.id} value={m.id}>{m.name} — {m.desc}</option>)}
            </select>
          </Box>

          <Box flexDirection="column" gap={0.5}>
            <Text>Model B (Opponent):</Text>
            <select value={modelB} onChange={e => setModelB(e.target.value)} style={{ backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.5rem' }}>
              {DEBATE_MODELS.map(m => <option key={m.id} value={m.id}>{m.name} — {m.desc}</option>)}
            </select>
          </Box>

          <Box flexDirection="row" gap={2} alignItems="center">
            <Text>Rounds:</Text>
            <select value={rounds} onChange={e => setRounds(Number(e.target.value))} style={{ width: 60 }}>
              {[1,2,3,4,5].map(r => <option key={r} value={r}>{r}</option>)}
            </select>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <input type="checkbox" checked={useSkills} onChange={e => setUseSkills(e.target.checked)} />
              <Text>Use skill evidence</Text>
            </label>
          </Box>

          <Box flexDirection="row" gap={1} marginTop={1}>
            <button
              type="submit"
              disabled={running || !question.trim() || modelA === modelB}
              style={{ padding: '0.5rem 1rem', backgroundColor: running ? '#333' : '#cc4400', color: '#fff', border: 'none' }}
            >
              {running ? 'Debating...' : 'Start Debate'}
            </button>
            <button type="button" onClick={() => dialog.clear()} style={{ padding: '0.5rem 1rem', backgroundColor: '#333', color: '#fff', border: 'none' }}>
              Cancel
            </button>
          </Box>
        </Box>
      </form>

      {result && (
        <Box marginTop={1} flexDirection="column" gap={0.5}>
          <Text bold>Results:</Text>
          {result.error ? <Text color="red">Error: {result.error}</Text> : (
            <>
              <Box flexDirection="column" gap={0.5}>
                {result.history && Object.entries(result.history).map(([model, contrib]) => (
                  <Box key={model} borderStyle="round" borderColor="gray" padding={1} marginBottom={1}>
                    <Text bold color="cyan">{model}:</Text>
                    <Text style={{ fontSize: 11 }}>{String(contrib).slice(0, 500)}...</Text>
                  </Box>
                ))}
              </Box>
              <Box borderStyle="round" borderColor="green" padding={1} marginTop={1}>
                <Text bold color="green">Synthesized (Model B):</Text>
                <Text style={{ fontSize: 11 }}>{String(result.final).slice(0, 1000)}...</Text>
              </Box>
            </>
          )}
        </Box>
      )}
    </Box>
  );
}