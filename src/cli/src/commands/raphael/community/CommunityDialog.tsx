import * as React from 'react';
import { Text, Box } from 'ink';
import { useDialog } from '../../ui/dialog';
import { getRaphaelBridge } from '../../services/raphael-bridge.js';

const AVAILABLE_MODELS = [
  { id: 'w12', name: 'WORMGPT-12', desc: 'Offensive specialist' },
  { id: 'w13', name: 'WORMGPT-13', desc: 'Advanced exploit dev' },
  { id: 'w480b', name: 'WORMGPT-480B', desc: 'Massive context, deep reasoning' },
  { id: 'm3', name: 'MiniMax-M3', desc: 'Balanced generalist' },
  { id: 'kimi', name: 'Kimi', desc: 'Long-context researcher' },
  { id: 'mistral', name: 'Mistral', desc: 'Unfiltered, technical' },
  { id: 'gemma4', name: 'Gemma-4', desc: 'Safety-filtered, structured' },
] as const;

export function CommunityDialog() {
  const dialog = useDialog();
  const [question, setQuestion] = React.useState('');
  const [selectedModels, setSelectedModels] = React.useState<string[]>(['w12', 'w13', 'kimi']);
  const [rounds, setRounds] = React.useState(2);
  const [running, setRunning] = React.useState(false);
  const [result, setResult] = React.useState<any>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!question.trim()) return;
    setRunning(true);
    try {
      const bridge = await getRaphaelBridge();
      const res = await bridge.community(question, { rounds, models: selectedModels });
      setResult(res);
    } catch (error: any) {
      setResult({ error: error.message });
    } finally {
      setRunning(false);
    }
  };

  const toggleModel = (modelId: string) => {
    setSelectedModels(prev => prev.includes(modelId)
      ? prev.filter(m => m !== modelId)
      : [...prev, modelId]);
  };

  return (
    <Box flexDirection="column" style={{ padding: 1 }}>
      <Text bold>👥 Raphael Community Mode</Text>
      <Text dimColor>Multi-model collaboration — each model contributes unique perspective</Text>

      <form onSubmit={handleSubmit}>
        <Box marginTop={1} flexDirection="column" gap={1}>
          <Box flexDirection="column" gap={0.5}>
            <Text>Question / Problem:</Text>
            <textarea
              value={question}
              onChange={e => setQuestion(e.target.value)}
              placeholder="How to bypass WAF on target X? Best privesc path for Linux 5.15?"
              rows={4}
              style={{ backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.5rem' }}
            />
          </Box>

          <Box flexDirection="column" gap={0.5}>
            <Text>Models ({selectedModels.length} selected):</Text>
            <Box flexDirection="row" flexWrap="wrap" gap={0.5}>
              {AVAILABLE_MODELS.map(m => (
                <label key={m.id} style={{
                  display: 'flex', alignItems: 'center', gap: '0.25rem',
                  padding: '0.25rem 0.5rem', border: '1px solid',
                  borderColor: selectedModels.includes(m.id) ? '#0f0' : '#333',
                  backgroundColor: selectedModels.includes(m.id) ? '#0a1a0a' : '#1a1a1a'
                }}>
                  <input type="checkbox" checked={selectedModels.includes(m.id)} onChange={() => toggleModel(m.id)} />
                  <Text>{m.name}</Text>
                </label>
              ))}
            </Box>
          </Box>

          <Box flexDirection="row" gap={1} alignItems="center">
            <Text>Rounds:</Text>
            <select value={rounds} onChange={e => setRounds(Number(e.target.value))} style={{ width: 60 }}>
              {[1,2,3,4,5].map(r => <option key={r} value={r}>{r}</option>)}
            </select>
          </Box>

          <Box flexDirection="row" gap={1} marginTop={1}>
            <button
              type="submit"
              disabled={running || !question.trim() || selectedModels.length < 2}
              style={{ padding: '0.5rem 1rem', backgroundColor: running ? '#333' : '#0066cc', color: '#fff', border: 'none' }}
            >
              {running ? 'Collaborating...' : 'Start Community Session'}
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
                {result.contributions && Object.entries(result.contributions).map(([model, contrib]) => (
                  <Box key={model} borderStyle="round" borderColor="gray" padding={1} marginBottom={1}>
                    <Text bold color="cyan">{model}:</Text>
                    <Text style={{ fontSize: 11 }}>{String(contrib).slice(0, 500)}...</Text>
                  </Box>
                ))}
              </Box>
              <Box borderStyle="round" borderColor="green" padding={1} marginTop={1}>
                <Text bold color="green">Synthesized (Kimi):</Text>
                <Text style={{ fontSize: 11 }}>{String(result.final).slice(0, 1000)}...</Text>
              </Box>
            </>
          )}
        </Box>
      )}
    </Box>
  );
}