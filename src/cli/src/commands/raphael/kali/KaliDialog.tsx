import * as React from 'react';
import { Text, Box } from 'ink';
import { getRaphaelBridge } from '../../../services/raphael-bridge.js';

const COMMON_TOOLS = [
  { id: 'nuclei', name: 'Nuclei', desc: 'Vulnerability scanner', args: '-u {target} -json -silent' },
  { id: 'nmap', name: 'Nmap', desc: 'Network mapper', args: '-sS -sV -T4 {target}' },
  { id: 'sqlmap', name: 'SQLMap', desc: 'SQL injection', args: '-u {url} --batch --random-agent' },
  { id: 'hashcat', name: 'Hashcat', desc: 'Password cracking', args: '-m 0 -a 0 hash.txt wordlist.txt' },
  { id: 'msfconsole', name: 'Metasploit', desc: 'Exploit framework', args: '-q -x "use exploit/..."' },
  { id: 'impacket-secretsdump', name: 'SecretsDump', desc: 'Dump credentials', args: 'domain/user:pass@target' },
  { id: 'crackmapexec', name: 'CrackMapExec', desc: 'AD enumeration', args: 'smb {target} -u user -p pass' },
  { id: 'bloodhound', name: 'BloodHound', desc: 'AD graph analysis', args: '-c all -d domain -u user -p pass -ns {target}' },
  { id: 'kerbrute', name: 'Kerbrute', desc: 'Kerberos enumeration', args: 'userenum --dc {target} users.txt' },
  { id: 'gobuster', name: 'Gobuster', desc: 'Directory brute force', args: 'dir -u {target} -w wordlist.txt' },
  { id: 'ffuf', name: 'FFUF', desc: 'Fast fuzzer', args: '-u {target}/FUZZ -w wordlist.txt' },
  { id: 'nikto', name: 'Nikto', desc: 'Web server scanner', args: '-h {target}' },
  { id: 'dirb', name: 'DIRB', desc: 'Web content scanner', args: '{target}' },
  { id: 'hydra', name: 'Hydra', desc: 'Login cracker', args: '-L users.txt -P passes.txt {target} ssh' },
  { id: 'john', name: 'John the Ripper', desc: 'Password cracker', args: '--wordlist=wordlist.txt hash.txt' },
  { id: 'enum4linux', name: 'enum4linux', desc: 'SMB enumeration', args: '-a {target}' },
  { id: 'smbclient', name: 'smbclient', desc: 'SMB client', args: '//{target}/share -U user' },
  { id: 'rpcclient', name: 'rpcclient', desc: 'RPC client', args: '-U user%pass {target}' },
  { id: 'ldapsearch', name: 'ldapsearch', desc: 'LDAP search', args: '-x -H ldap://{target} -D "cn=admin" -w pass' },
  { id: 'dig', name: 'dig', desc: 'DNS lookup', args: '{target} AXFR' },
  { id: 'dnsrecon', name: 'dnsrecon', desc: 'DNS enumeration', args: '-d {target} -t std' },
] as const;

export function KaliDialog() {
  const [tools, setTools] = React.useState<typeof COMMON_TOOLS>(COMMON_TOOLS);
  const [selectedTool, setSelectedTool] = React.useState<string>('nuclei');
  const [args, setArgs] = React.useState('');
  const [target, setTarget] = React.useState('');
  const [output, setOutput] = React.useState<string>('');
  const [running, setRunning] = React.useState(false);
  const [allTools, setAllTools] = React.useState<string[]>([]);

  React.useEffect(() => {
    loadTools();
  }, []);

  const loadTools = async () => {
    const bridge = await getRaphaelBridge();
    const result = await bridge.kaliListTools();
    if (result.tools) setAllTools(result.tools);
  };

  const handleRun = async () => {
    if (!selectedTool) return;
    setRunning(true);
    setOutput('');
    try {
      const bridge = await getRaphaelBridge();
      const finalArgs = args.replace('{target}', target).replace('{url}', target);
      const result = await bridge.kaliRun(selectedTool, finalArgs);
      setOutput(JSON.stringify(result, null, 2));
    } catch (error: any) {
      setOutput(`Error: ${error.message}`);
    } finally {
      setRunning(false);
    }
  };

  const handleNuclei = async () => {
    if (!target) return;
    setRunning(true);
    try {
      const bridge = await getRaphaelBridge();
      const result = await bridge.kaliNuclei(target);
      setOutput(JSON.stringify(result, null, 2));
    } catch (error: any) {
      setOutput(`Error: ${error.message}`);
    } finally {
      setRunning(false);
    }
  };

  return (
    <Box flexDirection="column" gap={1} style={{ padding: 1 }}>
      <Text bold>🛠️ Raphael Kali Tools</Text>
      <Text dimColor>300+ tools available locally or via remote kali-tools service</Text>

      <Box flexDirection="row" gap={2}>
        {/* Tool Selector */}
        <Box width={40} flexDirection="column" gap={0.5}>
          <Text>Available Tools:</Text>
          <input
            placeholder="Search tools..."
            onChange={e => setTools(COMMON_TOOLS.filter(t =>
              t.name.toLowerCase().includes(e.target.value.toLowerCase()) ||
              t.id.toLowerCase().includes(e.target.value.toLowerCase())
            ))}
            style={{ backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.25rem' }}
          />
          <Box style={{ maxHeight: 20, overflowY: 'auto' }} flexDirection="column" gap={0.25}>
            {tools.map(t => (
              <label key={t.id} style={{
                display: 'flex', alignItems: 'center', padding: '0.25rem',
                border: '1px solid', borderColor: selectedTool === t.id ? '#0f0' : '#333',
                backgroundColor: selectedTool === t.id ? '#0a1a0a' : '#1a1a1a', cursor: 'pointer'
              }}>
                <input type="radio" name="tool" checked={selectedTool === t.id} onChange={() => setSelectedTool(t.id)} />
                <Text>{t.name}</Text>
                <Text dimColor style={{ marginLeft: 1 }}>{t.desc}</Text>
              </label>
            ))}
          </Box>
        </Box>

        {/* Tool Config */}
        <Box flexDirection="column" gap={1} style={{ flex: 1 }}>
          {COMMON_TOOLS.find(t => t.id === selectedTool) && (
            <>
              <Text bold>{selectedTool.toUpperCase()}</Text>
              <Text dimColor>{COMMON_TOOLS.find(t => t.id === selectedTool)!.desc}</Text>

              <Box flexDirection="column" gap={0.5}>
                <Text>Target (for {selectedTool}):</Text>
                <input
                  value={target}
                  onChange={e => setTarget(e.target.value)}
                  placeholder="10.10.10.10 or https://target.com"
                  style={{ backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.5rem' }}
                />
              </Box>

              <Box flexDirection="column" gap={0.5}>
                <Text>Arguments:</Text>
                <input
                  value={args}
                  onChange={e => setArgs(e.target.value)}
                  placeholder={COMMON_TOOLS.find(t => t.id === selectedTool)?.args || ''}
                  style={{ backgroundColor: '#1a1a1a', color: '#fff', border: '1px solid #333', padding: '0.5rem' }}
                />
                <Text dimColor fontSize={11}>Use {target} placeholder for target substitution</Text>
              </Box>

              <Box flexDirection="row" gap={1}>
                <button onClick={handleRun} disabled={running} style={{ padding: '0.5rem 1rem', backgroundColor: running ? '#333' : '#0a0', color: '#000', border: 'none' }}>
                  {running ? 'Running...' : `Run ${selectedTool}`}
                </button>
                {selectedTool === 'nuclei' && (
                  <button onClick={handleNuclei} disabled={running || !target} style={{ padding: '0.5rem 1rem', backgroundColor: '#0066cc', color: '#fff', border: 'none' }}>
                    Run Nuclei Scan
                  </button>
                )}
              </Box>
            </>
          )}
        </Box>
      </Box>

      {output && (
        <Box marginTop={1} borderStyle="round" borderColor="gray" padding={1} style={{ maxHeight: 20, overflowY: 'auto' }}>
          <Text bold>Output:</Text>
          <Text style={{ fontSize: 10, fontFamily: 'monospace', whiteSpace: 'pre' }}>{output}</Text>
        </Box>
      )}
    </Box>
  );
}