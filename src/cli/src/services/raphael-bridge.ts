// Raphael Bridge Client - TypeScript wrapper for Python bridge
import { spawn, ChildProcessWithoutNullStreams } from 'child_process';
import { EventEmitter } from 'events';
import { resolve } from 'path';

export interface RaphaelRequest {
  id: string;
  method: string;
  params: Record<string, any>;
}

export interface RaphaelResponse {
  id: string;
  result?: any;
  error?: string;
}

type ResponseHandler = (response: RaphaelResponse) => void;

export class RaphaelBridge extends EventEmitter {
  private process: ChildProcessWithoutNullStreams | null = null;
  private pendingRequests = new Map<string, ResponseHandler>();
  private requestId = 0;
  private buffer = '';
  private bridgePath: string;

  constructor(bridgePath?: string) {
    super();
    this.bridgePath = bridgePath || resolve(__dirname, '../../../bridge/raphael_bridge.py');
  }

  async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.process = spawn('python3', [this.bridgePath], {
        stdio: ['pipe', 'pipe', 'pipe'],
        cwd: resolve(__dirname, '../../../'),
        env: { ...process.env, PYTHONPATH: resolve(__dirname, '../../../') }
      });

      this.process.stdout?.on('data', (data) => this.handleData(data.toString()));
      this.process.stderr?.on('data', (data) => console.error('[Raphael Bridge]', data.toString()));

      this.process.on('error', reject);
      this.process.on('exit', (code) => {
        if (code !== 0) this.emit('error', new Error(`Bridge exited with code ${code}`));
      });

      setTimeout(resolve, 500);
    });
  }

  private handleData(data: string) {
    this.buffer += data;
    const lines = this.buffer.split('\n');
    this.buffer = lines.pop() || '';

    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const response: RaphaelResponse = JSON.parse(line);
        const handler = this.pendingRequests.get(response.id);
        if (handler) {
          this.pendingRequests.delete(response.id);
          handler(response);
        }
      } catch (e) {
        console.error('[Raphael Bridge] Parse error:', line);
      }
    }
  }

  async call(method: string, params: Record<string, any> = {}): Promise<any> {
    const id = `req_${++this.requestId}_${Date.now()}`;

    return new Promise((resolve, reject) => {
      this.pendingRequests.set(id, (response) => {
        if (response.error) reject(new Error(response.error));
        else resolve(response.result);
      });

      const request: RaphaelRequest = { id, method, params };
      this.process?.stdin?.write(JSON.stringify(request) + '\n');

      setTimeout(() => {
        if (this.pendingRequests.has(id)) {
          this.pendingRequests.delete(id);
          reject(new Error(`Request ${method} timed out`));
        }
      }, 300000);
    });
  }

  async stop(): Promise<void> {
    this.process?.kill();
    this.process = null;
  }

  // === Convenience Methods ===

  // Modes
  async autonomous(target: string, options?: { phases?: string[]; persona?: string }): Promise<any> {
    return this.call('mode.autonomous', { target, ...options });
  }

  async community(question: string, options?: { rounds?: number; models?: string[] }): Promise<any> {
    return this.call('mode.community', { question, ...options });
  }

  async debate(question: string, options?: { rounds?: number; useSkills?: boolean; models?: string[] }): Promise<any> {
    return this.call('mode.debate', { question, ...options });
  }

  async deepResearch(topic: string, options?: Record<string, any>): Promise<any> {
    return this.call('mode.deep_research', { topic, ...options });
  }

  async scan(target: string, options?: Record<string, any>): Promise<any> {
    return this.call('mode.scan', { target, ...options });
  }

  // Agents
  async recon(target: string, depth?: string): Promise<any> {
    return this.call('agent.recon', { target, depth });
  }

  async exploit(target: string, vulnInfo?: any): Promise<any> {
    return this.call('agent.exploit', { target, vuln_info: vulnInfo });
  }

  async postex(session: any): Promise<any> {
    return this.call('agent.postex', { session });
  }

  async engage(target: string, chain?: string): Promise<any> {
    return this.call('agent.engage', { target, chain });
  }

  // C2 / Implants
  async buildImplant(config: any): Promise<any> {
    return this.call('c2.build_implant', { config });
  }

  async deployImplant(implantPath: string, target: string, method?: string): Promise<any> {
    return this.call('c2.deploy', { implant_path: implantPath, target, method });
  }

  async listBeacons(): Promise<any> {
    return this.call('c2.list_beacons', {});
  }

  async taskBeacon(beaconId: string, task: any): Promise<any> {
    return this.call('c2.task_beacon', { beacon_id: beaconId, task });
  }

  async sliverConnect(config: any): Promise<any> {
    return this.call('c2.sliver_connect', { config });
  }

  // Exploit
  async generateExploit(vulnType: string, targetInfo: any): Promise<any> {
    return this.call('exploit.generate', { vuln_type: vulnType, target_info: targetInfo });
  }

  async relayChain(target: string, chainConfig: any[]): Promise<any> {
    return this.call('exploit.relay_chain', { target, chain_config: chainConfig });
  }

  async searchPayloads(query?: string, category?: string): Promise<any> {
    return this.call('exploit.payload_db', { query: query || '', category });
  }

  // Kali Tools
  async kaliRun(tool: string, args?: string, timeout?: number): Promise<any> {
    return this.call('kali.run', { tool, args: args || '', timeout: timeout || 300 });
  }

  async kaliNuclei(target: string, options?: { templates?: string[]; severity?: string; rateLimit?: number }): Promise<any> {
    return this.call('kali.nuclei', { target, ...options });
  }

  async kaliSqlmap(url: string, args?: string): Promise<any> {
    return this.call('kali.sqlmap', { url, args: args || '' });
  }

  async kaliHashcat(args?: string): Promise<any> {
    return this.call('kali.hashcat', { args: args || '' });
  }

  async kaliImpacket(script: string, args?: string): Promise<any> {
    return this.call('kali.impacket', { script, args: args || '' });
  }

  async kaliListTools(): Promise<any> {
    return this.call('kali.list_tools', {});
  }

  // Harvester / Intel
  async harvesterRunCycle(target?: string): Promise<any> {
    return this.call('harvester.run_cycle', { target });
  }

  async harvesterSearchTechniques(query: string, category?: string): Promise<any> {
    return this.call('harvester.search_techniques', { query, category });
  }

  async harvesterGetCVEs(keyword?: string, days?: number): Promise<any> {
    return this.call('harvester.get_cves', { keyword: keyword || '', days: days || 30 });
  }

  // Conductor / Brain
  async conductorCall(prompt: string, model?: string, category?: string): Promise<any> {
    return this.call('conductor.call', { prompt, model: model || 'kimi', category: category || 'default' });
  }

  async conductorSelectStrategy(context: string, findings: any[]): Promise<any> {
    return this.call('conductor.select_strategy', { context, findings });
  }

  async brainAnalytics(): Promise<any> {
    return this.call('brain.analytics', {});
  }

  async brainMemoryStore(key: string, value: any, type?: string): Promise<any> {
    return this.call('brain.memory_store', { key, value, memory_type: type || 'episodic' });
  }

  async brainMemoryRecall(query: string, type?: string, limit?: number): Promise<any> {
    return this.call('brain.memory_recall', { query, memory_type: type || 'episodic', limit: limit || 10 });
  }

  // Models / Personas
  async modelCall(model: string, messages: any[], options?: any): Promise<any> {
    return this.call('model.call', { model, messages, ...options });
  }

  async setPersona(persona: string): Promise<any> {
    return this.call('persona.set', { persona });
  }

  async resolvePersona(persona: string): Promise<any> {
    return this.call('persona.resolve', { persona });
  }

  // Target / Scope
  async setTarget(target: string): Promise<any> {
    return this.call('target.set', { target });
  }

  async profileTarget(target: string): Promise<any> {
    return this.call('target.profile', { target });
  }

  async setScope(scope: any): Promise<any> {
    return this.call('scope.set', { scope });
  }
}

let bridgeInstance: RaphaelBridge | null = null;

export async function getRaphaelBridge(): Promise<RaphaelBridge> {
  if (!bridgeInstance) {
    bridgeInstance = new RaphaelBridge();
    await bridgeInstance.start();
  }
  return bridgeInstance;
}

export async function closeRaphaelBridge(): Promise<void> {
  if (bridgeInstance) {
    await bridgeInstance.stop();
    bridgeInstance = null;
  }
}