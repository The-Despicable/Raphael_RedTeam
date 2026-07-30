import * as React from 'react';
import { Text, Box } from 'ink';
import { getRaphaelBridge } from '../../../../../services/raphael-bridge.js';

export function DeepResearchDialog() {
  const [topic, setTopic] = React.useState('');
  const [running, setRunning] = React.useState(false);
  const [result, setResult] = React.useState<any>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!topic.trim()) return;
    setRunning(true);
    try {
      const bridge = await getRaphaelBridge();
      const res = await bridge.deepResearch(topic);
      setResult(res);
    } catch (error: any) {
      setResult({ error: error.message });
    } finally {
      setRunning(false);
    }
  };

  return (
    <Box flexDirection="column" style={{ padding: 1 }}>
      <Text bold>🔬 Raphael Deep Research</Text>
      <Text dimColor>5-phase methodology with adversarial verification and recency check</Text>

      <form onSubmit={handleSubmit}>
        <Box marginTop={1} flexDirection="column" gap={1}>
          <Box flexDirection="column" gap={0.5}>
            <Text>Research Topic:</Text>
            <textarea
              value={topic}
              onChange={e => setTopic(e.target.value)}
              placeholder="Latest CVE exploitation techniques for Linux kernel 6.x? Best OPSEC practices for long-term access?"
              rows={4}
              style={{ backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.5rem' }}
            />
          </Box>

          <button
            type="submit"
            disabled={running || !topic.trim()}
            style={{ padding: '0.5rem 1rem', backgroundColor: running ? '#333' : '#6600cc', color: '#fff', border: 'none' }}
          >
            {running ? 'Researching...' : 'Start Deep Research'}
          </button>
        </Box>
      </form>

      {result && (
        <Box marginTop={1} flexDirection="column" gap={0.5}>
          <Text bold>Results:</Text>
          {result.error ? <Text color="red">Error: {result.error}</Text> : (
            <>
              <Box borderStyle="round" borderColor="green" padding={1} marginTop={1}>
                <Text bold color="green">Synthesized Report:</Text>
                <Text style={{ fontSize: 11, whiteSpace: 'pre-wrap' }}>{String(result.report || result.final || result).slice(0, 3000)}...</Text>
              </Box>
            </>
          )}
        </Box>
      )}
    </Box>
  );
}