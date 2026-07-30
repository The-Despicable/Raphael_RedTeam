import * as React from 'react';
import { Text, Box } from 'ink';
import { getRaphaelBridge } from '../../../../../services/raphael-bridge.js';

export function SliverDialog() {
  const [config, setConfig] = React.useState({
    host: '127.0.0.1',
    port: 31337,
    operator: 'opencode',
    password: '',
    lport: 443,
  });
  const [connected, setConnected] = React.useState(false);
  const [output, setOutput] = React.useState<string>('');
  const [running, setRunning] = React.useState(false);

  const handleConnect = async () => {
    setRunning(true);
    setOutput('');
    try {
      const bridge = await getRaphaelBridge();
      const result = await bridge.sliverConnect(config);
      setOutput(JSON.stringify(result, null, 2));
      if (!result.error) setConnected(true);
    } catch (error: any) {
      setOutput(`Error: ${error.message}`);
    } finally {
      setRunning(false);
    }
  };

  return (
    <Box flexDirection="column" gap={1} style={{ padding: 1 }}>
      <Text bold>🔗 Sliver C2 Integration</Text>
      <Text dimColor>Connect to Sliver server for C2 management</Text>

      <Box flexDirection="column" gap={0.5}>
        <Box flexDirection="column" gap={0.5}>
          <Text>Server Host:</Text>
          <input
            value={config.host}
            onChange={e => setConfig({...config, host: e.target.value})}
            style={{ backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.5rem' }}
          />
        </Box>

        <Box flexDirection="column" gap={0.5}>
          <Text>Server Port:</Text>
          <input
            type="number"
            value={config.port}
            onChange={e => setConfig({...config, port: parseInt(e.target.value)})}
            style={{ backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.5rem' }}
          />
        </Box>

        <Box flexDirection="column" gap={0.5}>
          <Text>Operator:</Text>
          <input
            value={config.operator}
            onChange={e => setConfig({...config, operator: e.target.value})}
            style={{ backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.5rem' }}
          />
        </Box>

        <Box flexDirection="column" gap={0.5}>
          <Text>Password:</Text>
          <input
            type="password"
            value={config.password}
            onChange={e => setConfig({...config, password: e.target.value})}
            style={{ backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.5rem' }}
          />
        </Box>

        <Box flexDirection="column" gap={0.5}>
          <Text>Listener Port (for implants):</Text>
          <input
            type="number"
            value={config.lport}
            onChange={e => setConfig({...config, lport: parseInt(e.target.value)})}
            style={{ backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.5rem' }}
          />
        </Box>

        <button onClick={handleConnect} disabled={running} style={{ padding: '0.5rem 1rem', backgroundColor: connected ? '#6600cc' : (running ? '#333' : '#0a0'), color: '#fff', border: 'none' }}>
          {connected ? 'Connected' : (running ? 'Connecting...' : 'Connect to Sliver')}
        </button>
      </Box>

      {output && (
        <Box marginTop={1} borderStyle="round" borderColor="gray" padding={1} style={{ maxHeight: 15, overflowY: 'auto' }}>
          <Text bold>Result:</Text>
          <Text style={{ fontSize: 10, fontFamily: 'monospace', whiteSpace: 'pre' }}>{output}</Text>
        </Box>
      )}
    </Box>
  );
}