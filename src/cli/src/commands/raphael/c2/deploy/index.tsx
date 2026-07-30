import * as React from 'react';
import { Text, Box } from 'ink';
import { getRaphaelBridge } from '../../../../../services/raphael-bridge.js';

export function DeployImplantDialog() {
  const [implantPath, setImplantPath] = React.useState('');
  const [target, setTarget] = React.useState('');
  const [method, setMethod] = React.useState('ssh');
  const [user, setUser] = React.useState('root');
  const [password, setPassword] = React.useState('');
  const [output, setOutput] = React.useState<string>('');
  const [running, setRunning] = React.useState(false);

  const handleDeploy = async () => {
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
    <Box flexDirection="column" gap={1}>
      <Text bold>🚀 Deploy Implant</Text>
      <Box flexDirection="column" gap={0.5}>
        <Text>Implant Path:</Text>
        <input value={implantPath} onChange={e => setImplantPath(e.target.value)} placeholder="/path/to/implant" />
      </Box>

      <Box flexDirection="column" gap={0.5}>
        <Text>Target:</Text>
        <input value={target} onChange={e => setTarget(e.target.value)} placeholder="10.10.10.10" />
      </Box>

      <Box flexDirection="column" gap={0.5}>
        <Text>Method:</Text>
        <select value={method} onChange={e => setMethod(e.target.value)}>
          <option value="ssh">SSH</option>
          <option value="sshpass">SSH with password</option>
          <option value="winrm">WinRM</option>
        </select>
      </Box>

      <Box flexDirection="column" gap={0.5}>
        <Text>User:</Text>
        <input value={user} onChange={e => setUser(e.target.value)} />
      </Box>

      <Box flexDirection="column" gap={0.5}>
        <Text>Password (if sshpass):</Text>
        <input type="password" value={password} onChange={e => setPassword(e.target.value)} />
      </Box>

      <button onClick={handleDeploy} disabled={running} style={{ padding: '0.5rem 1rem', backgroundColor: running ? '#333' : '#0a0', color: '#000', border: 'none' }}>
        {running ? 'Deploying...' : 'Deploy Implant'}
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