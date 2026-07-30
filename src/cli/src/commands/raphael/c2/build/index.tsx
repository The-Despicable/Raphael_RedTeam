import * as React from 'react';
import { Text, Box } from 'ink';
import { getRaphaelBridge } from '../../../../../services/raphael-bridge.js';

export function BuildImplantDialog() {
  const [config, setConfig] = React.useState({
    backend: 'native',
    protocol: 'https',
    host: '10.10.14.1',
    port: 443,
    sleep: 60,
    jitter: 10,
    proxy: '',
    headers: '{}',
    killdate: '',
  });

  const [output, setOutput] = React.useState<string>('');
  const [running, setRunning] = React.useState(false);

  const handleBuild = async () => {
    setRunning(true);
    setOutput('');
    try {
      const bridge = await getRaphaelBridge();
      const result = await bridge.buildImplant(config);
      setOutput(JSON.stringify(result, null, 2));
    } catch (error: any) {
      setOutput(`Error: ${error.message}`);
    } finally {
      setRunning(false);
    }
  };

  return (
    <Box flexDirection="column" gap={1}>
      <Text bold>🔧 Build Implant</Text>
      <select value={config.backend} onChange={e => setConfig({...config, backend: e.target.value})}>
        <option value="native">Native (Go/Rust)</option>
        <option value="sliver">Sliver</option>
        <option value="noop">No-Op (Testing)</option>
      </select>

      <Box flexDirection="column" gap={0.5}>
        <Text>Protocol:</Text>
        <select value={config.protocol} onChange={e => setConfig({...config, protocol: e.target.value})}>
          <option value="https">HTTPS</option>
          <option value="http">HTTP</option>
          <option value="dns">DNS</option>
        </select>
      </Box>

      <Box flexDirection="column" gap={0.5}>
        <Text>C2 Host:</Text>
        <input value={config.host} onChange={e => setConfig({...config, host: e.target.value})} />
      </Box>

      <Box flexDirection="column" gap={0.5}>
        <Text>C2 Port:</Text>
        <input type="number" value={config.port} onChange={e => setConfig({...config, port: parseInt(e.target.value)})} />
      </Box>

      <Box flexDirection="column" gap={0.5}>
        <Text>Sleep (seconds):</Text>
        <input type="number" value={config.sleep} onChange={e => setConfig({...config, sleep: parseInt(e.target.value)})} />
      </Box>

      <Box flexDirection="column" gap={0.5}>
        <Text>Jitter (%):</Text>
        <input type="number" value={config.jitter} onChange={e => setConfig({...config, jitter: parseInt(e.target.value)})} />
      </Box>

      <Box flexDirection="column" gap={0.5}>
        <Text>Proxy (optional):</Text>
        <input value={config.proxy} onChange={e => setConfig({...config, proxy: e.target.value})} placeholder="socks5://127.0.0.1:9050" />
      </Box>

      <Box flexDirection="column" gap={0.5}>
        <Text>Headers (JSON):</Text>
        <input value={config.headers} onChange={e => setConfig({...config, headers: e.target.value})} />
      </Box>

      <Box flexDirection="column" gap={0.5}>
        <Text>Kill Date (YYYY-MM-DD):</Text>
        <input value={config.killdate} onChange={e => setConfig({...config, killdate: e.target.value})} placeholder="2026-12-31" />
      </Box>

      <button onClick={handleBuild} disabled={running} style={{ padding: '0.5rem 1rem', backgroundColor: running ? '#333' : '#0a0', color: '#000', border: 'none' }}>
        {running ? 'Building...' : 'Build Implant'}
      </button>

      {output && (
        <Box marginTop={1} borderStyle="round" borderColor="gray" padding={1} style={{ maxHeight: 15, overflowY: 'auto' }}>
          <Text bold>Result:</Text>
          <Text style={{ fontSize: 10, fontFamily: 'monospace', whiteSpace: 'pre' }}>{output}</Text>
        </Box>
      )}
    </Box>
  );
}