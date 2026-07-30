import * as React from 'react';
import { Text, Box } from 'ink';
import { getRaphaelBridge } from '../../../../../services/raphael-bridge.js';

export function HarvesterDialog() {
  const [target, setTarget] = React.useState('');
  const [cycles, setCycles] = React.useState<any[]>([]);
  const [techniques, setTechniques] = React.useState<any[]>([]);
  const [cves, setCves] = React.useState<any[]>([]);
  const [query, setQuery] = React.useState('');
  const [running, setRunning] = React.useState(false);

  const runCycle = async () => {
    setRunning(true);
    try {
      const bridge = await getRaphaelBridge();
      const result = await bridge.harvesterRunCycle(target || undefined);
      setCycles(prev => [result, ...prev]);
    } catch (error: any) {
      setCycles(prev => [{ error: error.message }, ...prev]);
    } finally {
      setRunning(false);
    }
  };

  const searchTechniques = async () => {
    setRunning(true);
    try {
      const bridge = await getRaphaelBridge();
      const result = await bridge.harvesterSearchTechniques(query);
      setTechniques(result);
    } catch (error: any) {
      setTechniques([{ error: error.message }]);
    } finally {
      setRunning(false);
    }
  };

  const getCVEs = async () => {
    setRunning(true);
    try {
      const bridge = await getRaphaelBridge();
      const result = await bridge.harvesterGetCVEs(query, 30);
      setCves(result);
    } catch (error: any) {
      setCves([{ error: error.message }]);
    } finally {
      setRunning(false);
    }
  };

  return (
    <Box flexDirection="column" gap={1} style={{ padding: 1 }}>
      <Text bold>🔍 Raphael Harvester</Text>
      <Text dimColor>Continuous threat intel: CVEs, GitHub PoCs, ATT&CK techniques</Text>

      <Box flexDirection="row" gap={2}>
        {/* Controls */}
        <Box width={50} flexDirection="column" gap={1}>
          <Box flexDirection="column" gap={0.5}>
            <Text>Target (optional):</Text>
            <input value={target} onChange={e => setTarget(e.target.value)} placeholder="Auto-discover if empty" />
          </Box>

          <button onClick={runCycle} disabled={running}>
            {running ? 'Harvesting...' : 'Run Harvest Cycle'}
          </button>

          <Box flexDirection="column" gap={0.5} marginTop={1}>
            <Text>Search Techniques:</Text>
            <input value={query} onChange={e => setQuery(e.target.value)} placeholder="e.g., privilege escalation, CVE-2024" />
            <button onClick={searchTechniques} disabled={running || !query.trim()}>Search</button>
          </Box>

          <button onClick={getCVEs} marginTop={1} disabled={running}>Get Recent CVEs (30 days)</button>
        </Box>

        {/* Results */}
        <Box style={{ flex: 1 }} flexDirection="column" gap={1}>
          {cycles.length > 0 && (
            <Box borderStyle="round" borderColor="gray" padding={1} style={{ maxHeight: 15, overflowY: 'auto' }}>
              <Text bold>Recent Cycles:</Text>
              {cycles.slice(0, 5).map((cycle, i) => (
                <Box key={i} marginTop={0.5} flexDirection="column" gap={0.25}>
                  <Text color="cyan">Cycle {cycle.cycle_id?.slice(0,8)} — {new Date(cycle.started * 1000).toLocaleString()}</Text>
                  <Text dimColor fontSize={11}>CVEs: {cycle.cve_new}/{cycle.cve_total} | Repos: {cycle.repo_new}/{cycle.repo_total} | Techniques: {cycle.techniques_extracted} extracted, {cycle.techniques_integrated} integrated</Text>
                  {cycle.errors.length > 0 && <Text color="red" fontSize={11}>Errors: {cycle.errors.join(', ')}</Text>}
                </Box>
              ))}
            </Box>
          )}

          {techniques.length > 0 && (
            <Box borderStyle="round" borderColor="green" padding={1} style={{ maxHeight: 20, overflowY: 'auto' }}>
              <Text bold color="green">Techniques Found:</Text>
              {techniques.map((t, i) => (
                <Box key={i} marginTop={0.5} paddingLeft={1}>
                  <Text bold>{t.technique_name} [{t.category}]</Text>
                  <Text dimColor fontSize={11}>{t.description}</Text>
                  <Text dimColor fontSize={10}>MITRE: {t.mitre_id} | Confidence: {t.confidence} | Source: {t.source_type}:{t.source_ref}</Text>
                </Box>
              ))}
            </Box>
          )}

          {cves.length > 0 && (
            <Box borderStyle="round" borderColor="yellow" padding={1} style={{ maxHeight: 20, overflowY: 'auto' }}>
              <Text bold color="yellow">Recent CVEs:</Text>
              {cves.slice(0, 20).map((cve, i) => (
                <Box key={i} marginTop={0.5} paddingLeft={1}>
                  <Text bold>{cve.id} — CVSS: {cve.cvss}</Text>
                  <Text dimColor fontSize={11}>{cve.description?.slice(0, 150)}...</Text>
                </Box>
              ))}
            </Box>
          )}
        </Box>
      </Box>
    </Box>
  );
}