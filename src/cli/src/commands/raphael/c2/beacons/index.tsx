import * as React from 'react';
import { Text, Box } from 'ink';
import { getRaphaelBridge } from '../../../../../services/raphael-bridge.js';

export function BeaconsDialog() {
  const [beacons, setBeacons] = React.useState<any[]>([]);
  const [selectedBeacon, setSelectedBeacon] = React.useState<any>(null);
  const [task, setTask] = React.useState('');
  const [output, setOutput] = React.useState<string>('');
  const [running, setRunning] = React.useState(false);

  const loadBeacons = async () => {
    const bridge = await getRaphaelBridge();
    const result = await bridge.listBeacons();
    setBeacons(result.beacons || result || []);
  };

  React.useEffect(() => {
    loadBeacons();
  }, []);

  const handleTask = async () => {
    if (!selectedBeacon || !task.trim()) return;
    setRunning(true);
    try {
      const bridge = await getRaphaelBridge();
      const result = await bridge.taskBeacon(selectedBeacon.id, { command: task });
      setOutput(JSON.stringify(result, null, 2));
    } catch (error: any) {
      setOutput(`Error: ${error.message}`);
    } finally {
      setRunning(false);
    }
  };

  return (
    <Box flexDirection="column" gap={1} style={{ padding: 1 }}>
      <Text bold>📡 C2 Beacons</Text>
      <button onClick={loadBeacons} disabled={running} style={{ padding: '0.5rem 1rem', backgroundColor: running ? '#333' : '#0066cc', color: '#fff', border: 'none' }}>
        {running ? 'Loading...' : 'Refresh Beacons'}
      </button>

      {beacons.length > 0 && (
        <Box flexDirection="column" gap={0.5} style={{ maxHeight: 15, overflowY: 'auto' }}>
          {beacons.map((b: any) => (
            <label key={b.id} style={{
              display: 'flex', alignItems: 'center', padding: '0.25rem',
              border: '1px solid', borderColor: selectedBeacon?.id === b.id ? '#0f0' : '#333',
              backgroundColor: selectedBeacon?.id === b.id ? '#0a1a0a' : '#1a1a1a', cursor: 'pointer'
            }}>
              <input type="radio" name="beacon" checked={selectedBeacon?.id === b.id} onChange={() => setSelectedBeacon(b)} />
              <Text>ID: {b.id?.slice(0,8)}</Text>
              <Text dimColor style={{ marginLeft: 1 }}>{b.status} • {b.host} • {b.last_seen ? new Date(b.last_seen * 1000).toLocaleString() : 'never'}</Text>
            </label>
          ))}
        </Box>
      )}

      {selectedBeacon && (
        <Box marginTop={1} flexDirection="column" gap={0.5}>
          <Text bold>Task Beacon: {selectedBeacon.id?.slice(0,8)}</Text>
          <input value={task} onChange={e => setTask(e.target.value)} placeholder="shell whoami / shell net user / download /tmp/file" style={{ width: '100%' }} />
          <button onClick={handleTask} disabled={running || !task.trim()} style={{ padding: '0.5rem 1rem', backgroundColor: running ? '#333' : '#0a0', color: '#000', border: 'none' }}>
            {running ? 'Tasking...' : 'Send Task'}
          </button>
        </Box>
      )}

      {output && (
        <Box marginTop={1} borderStyle="round" borderColor="gray" padding={1} style={{ maxHeight: 15, overflowY: 'auto' }}>
          <Text bold>Output:</Text>
          <Text style={{ fontSize: 10, fontFamily: 'monospace', whiteSpace: 'pre' }}>{output}</Text>
        </Box>
      )}
    </Box>
  );
}