import * as React from 'react';
import { Text, Box } from 'ink';
import { getRaphaelBridge } from '../../../../../services/raphael-bridge.js';

export function BrainDialog() {
  const [analytics, setAnalytics] = React.useState<any>(null);
  const [memoryQuery, setMemoryQuery] = React.useState('');
  const [memoryResults, setMemoryResults] = React.useState<any[]>([]);
  const [memoryType, setMemoryType] = React.useState<'episodic' | 'semantic'>('episodic');
  const [running, setRunning] = React.useState(false);

  const loadAnalytics = async () => {
    setRunning(true);
    try {
      const bridge = await getRaphaelBridge();
      const result = await bridge.brainAnalytics();
      setAnalytics(result);
    } catch (error: any) {
      setAnalytics({ error: error.message });
    } finally {
      setRunning(false);
    }
  };

  const searchMemory = async () => {
    if (!memoryQuery.trim()) return;
    setRunning(true);
    try {
      const bridge = await getRaphaelBridge();
      const result = await bridge.brainMemoryRecall(memoryQuery, memoryType);
      setMemoryResults(result);
    } catch (error: any) {
      setMemoryResults([{ error: error.message }]);
    } finally {
      setRunning(false);
    }
  };

  return (
    <Box flexDirection="column" gap={1} style={{ padding: 1 }}>
      <Text bold>🧠 Raphael Neural Brain</Text>
      <Text dimColor>Adaptive memory, strategy learning, operational analytics</Text>

      <Box flexDirection="row" gap={2}>
        {/* Analytics Panel */}
        <Box width={50} flexDirection="column" gap={1}>
          <Text bold>Analytics:</Text>
          <button onClick={loadAnalytics} disabled={running} style={{ padding: '0.5rem 1rem', backgroundColor: running ? '#333' : '#0066cc', color: '#fff', border: 'none' }}>
            {running ? 'Loading...' : 'Refresh Analytics'}
          </button>

          {analytics && (
            <Box borderStyle="round" borderColor="gray" padding={1} style={{ maxHeight: 25, overflowY: 'auto' }}>
              {analytics.error ? <Text color="red">Error: {analytics.error}</Text> : (
                <>
                  <Text>Total Engagements: {analytics.total_engagements}</Text>
                  <Text>Success Rate: {analytics.success_rate}%</Text>
                  <Text>Avg Phases/Engagement: {analytics.avg_phases}</Text>
                  <Text>Top Techniques:</Text>
                  {analytics.top_techniques?.map((t: any, i: number) => (
                    <Text key={i} paddingLeft={2} fontSize={11}>{t.name} — {t.count} uses ({t.success_rate}% success)</Text>
                  ))}
                  <Text>Persona Performance:</Text>
                  {analytics.persona_stats?.map((p: any, i: number) => (
                    <Text key={i} paddingLeft={2} fontSize={11}>{p.persona}: {p.wins}W/{p.losses}L ({p.win_rate}%)</Text>
                  ))}
                </>
              )}
            </Box>
          )}
        </Box>

        {/* Memory Panel */}
        <Box style={{ flex: 1 }} flexDirection="column" gap={1}>
          <Text bold>Memory Recall:</Text>
          <Box flexDirection="row" gap={1}>
            <select value={memoryType} onChange={e => setMemoryType(e.target.value as any)} style={{ backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.25rem' }}>
              <option value="episodic">Episodic (events)</option>
              <option value="semantic">Semantic (knowledge)</option>
            </select>
            <input
              value={memoryQuery}
              onChange={e => setMemoryQuery(e.target.value)}
              placeholder="Search memory..."
              style={{ flex: 1, backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.25rem' }}
            />
            <button onClick={searchMemory} disabled={running || !memoryQuery.trim()} style={{ padding: '0.5rem 1rem', backgroundColor: running ? '#333' : '#0066cc', color: '#fff', border: 'none' }}>
              {running ? 'Searching...' : 'Search'}
            </button>
          </Box>

          {memoryResults.length > 0 && (
            <Box borderStyle="round" borderColor="cyan" padding={1} style={{ maxHeight: 20, overflowY: 'auto' }}>
              {memoryResults.map((m, i) => (
                <Box key={i} marginTop={0.5} paddingLeft={1}>
                  <Text bold>{m.key}</Text>
                  <Text dimColor fontSize={11}>{JSON.stringify(m.value).slice(0, 200)}</Text>
                  <Text dimColor fontSize={10}>Timestamp: {new Date(m.timestamp * 1000).toLocaleString()}</Text>
                </Box>
              ))}
            </Box>
          )}
        </Box>
      </Box>
    </Box>
  );
}