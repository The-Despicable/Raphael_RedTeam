import * as React from 'react';
import { Text, Box } from 'ink';
import { getRaphaelBridge } from '../../../../../services/raphael-bridge.js';

export function DeployImplantDialog() {
  const [implantPath, setImplantPath] = React.useState('');
  const [target, setTarget] = React.useState('');
  const [method, setMethod] = React.useState('ssh');
  const [user, setUser] = React.useState('root');
  const [password, setPassword] = React.useState('');
  const [keyPath, setKeyPath] = React.useState('~/.ssh/id_rsa');
  const [output, setOutput] = React.useState<string>('');
  const [running, setRunning] = React.useState(false);

  const handleDeploy = async () => {
    if (!implantPath || !target) return;
    setRunning(true);
    setOutput('');
    try {
      const bridge = await getRaphaelBridge();
      const result = await bridge.deployImplant(implantPath, target, method);
      setOutput(JSON.stringify(result, null, 2));
    } catch (error: any) {
      setOutput(`Error: ${error.message}`);
    } finally {
      setRunning(false);
    }
  };

  return (
    <Box flexDirection="column" gap={1} style={{ padding: 1 }}>
      <Text bold>🚀 Deploy Implant</Text>
      <Text dimColor>Deliver implant to target via SSH/SCP</Text>

      <Box flexDirection="column" gap={0.5}>
        <Text>Implant Path:</Text>
        <input
          value={implantPath}
          onChange={e => setImplantPath(e.target.value)}
          placeholder="/tmp/implant.bin"
          style={{ backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.5rem' }}
        />
      </Box>

      <Box flexDirection="column" gap={0.5}>
        <Text>Target (IP or hostname):</Text>
        <input
          value={target}
          onChange={e => setTarget(e.target.value)}
          placeholder="10.10.10.10"
          style={{ backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.5rem' }}
        />
      </Box>

      <Box flexDirection="column" gap={0.5}>
        <Text>Method:</Text>
        <select
          value={method}
          onChange={e => setMethod(e.target.value)}
          style={{ backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.5rem' }}
        >
          <option value="ssh">SSH (with key)</option>
          <option value="sshpass">SSH (with password)</option>
          <option value="scp">SCP only</option>
        </select>
      </Box>

      {method === 'ssh' && (
        <Box flexDirection="column" gap={0.5}>
          <Text>SSH User:</Text>
          <input
            value={user}
            onChange={e => setUser(e.target.value)}
            style={{ backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.5rem' }}
          />
        </Box>
      )}

      {method === 'ssh' && (
        <Box flexDirection="column" gap={0.5}>
          <Text>SSH Key Path:</Text>
          <input
            value={keyPath}
            onChange={e => setKeyPath(e.target.value)}
            style={{ backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.5rem' }}
          />
        </Box>
      )}

      {method === 'sshpass' && (
        <Box flexDirection="column" gap={0.5}>
          <Text>Password:</Text>
          <input
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            style={{ backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.5rem' }}
          />
        </Box>
      )}

      <button onClick={handleDeploy} disabled={running} style={{ padding: '0.5rem 1rem', backgroundColor: running ? '#333' : '#0066cc', color: '#fff', border: 'none' }}>
        {running ? 'Deploying...' : 'Deploy Implant'}
      </button>

      {output && (
        <Box marginTop={1} borderStyle="round" borderColor="gray" padding={1} style={{ maxHeight: 20, overflowY: 'auto' }}>
          <Text bold>Result:</Text>
          <Text style={{ fontSize: 10, fontFamily: 'monospace', whiteSpace: 'pre' }}>{output}</Text>
        </Box>
      )}
    </Box>
  );
}