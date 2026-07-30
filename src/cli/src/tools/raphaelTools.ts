import { Tool } from '../Tool.js'
import { getRaphaelBridge } from '../services/raphael-bridge.js'

async function callBridge(method: string, params: Record<string, any> = {}) {
  const bridge = await getRaphaelBridge()
  return bridge.call(method, params)
}

export const raphaelAutonomousTool: Tool = {
  name: 'raphael_autonomous',
  description: 'Launch full autonomous operation against a target',
  parameters: {
    type: 'object',
    properties: {
      target: { type: 'string', description: 'Target IP, domain, or CIDR' },
      phases: { type: 'array', items: { type: 'string' }, description: 'Phases to run' },
      persona: { type: 'string', enum: ['stealth', 'aggressive', 'z3r0', 'blackhat', 'redteam'] },
    },
    required: ['target'],
  },
  execute: async (params: any) => callBridge('mode.autonomous', params),
}

export const raphaelCommunityTool: Tool = {
  name: 'raphael_community',
  description: 'Multi-model collaborative problem solving',
  parameters: {
    type: 'object',
    properties: {
      question: { type: 'string' },
      models: { type: 'array', items: { type: 'string' } },
      rounds: { type: 'number' },
    },
    required: ['question'],
  },
  execute: async (params: any) => callBridge('mode.community', params),
}

export const raphaelDebateTool: Tool = {
  name: 'raphael_debate',
  description: 'Adversarial debate between two models with skill evidence',
  parameters: {
    type: 'object',
    properties: {
      question: { type: 'string' },
      models: { type: 'array', items: { type: 'string' } },
      rounds: { type: 'number' },
      useSkills: { type: 'boolean' },
    },
    required: ['question'],
  },
  execute: async (params: any) => callBridge('mode.debate', params),
}

export const raphaelDeepResearchTool: Tool = {
  name: 'raphael_deep_research',
  description: 'Deep research with phased methodology and adversarial verification',
  parameters: {
    type: 'object',
    properties: {
      topic: { type: 'string' },
    },
    required: ['topic'],
  },
  execute: async (params: any) => callBridge('mode.deep_research', params),
}

export const raphaelScanTool: Tool = {
  name: 'raphael_scan',
  description: 'Reconnaissance scanning against a target',
  parameters: {
    type: 'object',
    properties: {
      target: { type: 'string' },
    },
    required: ['target'],
  },
  execute: async (params: any) => callBridge('mode.scan', params),
}

export const raphaelReconTool: Tool = {
  name: 'raphael_recon',
  description: 'Reconnaissance agent for passive/active information gathering',
  parameters: {
    type: 'object',
    properties: {
      target: { type: 'string' },
      depth: { type: 'string' },
    },
    required: ['target'],
  },
  execute: async (params: any) => callBridge('agent.recon', params),
}

export const raphaelExploitTool: Tool = {
  name: 'raphael_exploit',
  description: 'Exploitation agent for vulnerability exploitation',
  parameters: {
    type: 'object',
    properties: {
      target: { type: 'string' },
      vulnInfo: { type: 'object' },
    },
    required: ['target'],
  },
  execute: async (params: any) => callBridge('agent.exploit', params),
}

export const raphaelPostExTool: Tool = {
  name: 'raphael_postex',
  description: 'Post-exploitation agent for privilege escalation and lateral movement',
  parameters: {
    type: 'object',
    properties: {
      session: { type: 'object' },
    },
    required: ['session'],
  },
  execute: async (params: any) => callBridge('agent.postex', params),
}

export const raphaelEngageTool: Tool = {
  name: 'raphael_engage',
  description: 'Engage full kill chain against target',
  parameters: {
    type: 'object',
    properties: {
      target: { type: 'string' },
      chain: { type: 'string' },
    },
    required: ['target'],
  },
  execute: async (params: any) => callBridge('agent.engage', params),
}

export const raphaelC2BuildImplantTool: Tool = {
  name: 'raphael_c2_build_implant',
  description: 'Build a C2 implant (native, Sliver, or noop)',
  parameters: {
    type: 'object',
    properties: {
      config: { type: 'object' },
    },
    required: ['config'],
  },
  execute: async (params: any) => callBridge('c2.build_implant', params),
}

export const raphaelC2DeployImplantTool: Tool = {
  name: 'raphael_c2_deploy_implant',
  description: 'Deploy implant to target',
  parameters: {
    type: 'object',
    properties: {
      implantPath: { type: 'string' },
      target: { type: 'string' },
      method: { type: 'string' },
    },
    required: ['implantPath', 'target'],
  },
  execute: async (params: any) => callBridge('c2.deploy', params),
}

export const raphaelC2ListBeaconsTool: Tool = {
  name: 'raphael_c2_list_beacons',
  description: 'List active C2 beacons',
  parameters: { type: 'object', properties: {} },
  execute: async () => callBridge('c2.list_beacons', {}),
}

export const raphaelC2TaskBeaconTool: Tool = {
  name: 'raphael_c2_task_beacon',
  description: 'Task a specific beacon',
  parameters: {
    type: 'object',
    properties: {
      beaconId: { type: 'string' },
      task: { type: 'object' },
    },
    required: ['beaconId', 'task'],
  },
  execute: async (params: any) => callBridge('c2.task_beacon', params),
}

export const raphaelC2SliverConnectTool: Tool = {
  name: 'raphael_c2_sliver_connect',
  description: 'Connect to Sliver C2 server',
  parameters: {
    type: 'object',
    properties: {
      config: { type: 'object' },
    },
    required: ['config'],
  },
  execute: async (params: any) => callBridge('c2.sliver_connect', params),
}

export const raphaelExploitGenerateTool: Tool = {
  name: 'raphael_exploit_generate',
  description: 'Generate exploit code for a vulnerability type',
  parameters: {
    type: 'object',
    properties: {
      vulnType: { type: 'string' },
      targetInfo: { type: 'object' },
    },
    required: ['vulnType', 'targetInfo'],
  },
  execute: async (params: any) => callBridge('exploit.generate', params),
}

export const raphaelExploitRelayChainTool: Tool = {
  name: 'raphael_exploit_relay_chain',
  description: 'Execute exploit relay chain',
  parameters: {
    type: 'object',
    properties: {
      target: { type: 'string' },
      chainConfig: { type: 'array', items: { type: 'object' } },
    },
    required: ['target', 'chainConfig'],
  },
  execute: async (params: any) => callBridge('exploit.relay_chain', params),
}

export const raphaelExploitPayloadDbTool: Tool = {
  name: 'raphael_exploit_payload_db',
  description: 'Search payload database',
  parameters: {
    type: 'object',
    properties: {
      query: { type: 'string' },
      category: { type: 'string' },
    },
  },
  execute: async (params: any) => callBridge('exploit.payload_db', params),
}

export const raphaelKaliRunTool: Tool = {
  name: 'raphael_kali_run',
  description: 'Execute any Kali Linux tool (300+ available)',
  parameters: {
    type: 'object',
    properties: {
      tool: { type: 'string' },
      args: { type: 'string' },
      timeout: { type: 'number' },
    },
    required: ['tool'],
  },
  execute: async (params: any) => callBridge('kali.run', params),
}

export const raphaelKaliNucleiTool: Tool = {
  name: 'raphael_kali_nuclei',
  description: 'Run Nuclei vulnerability scanner',
  parameters: {
    type: 'object',
    properties: {
      target: { type: 'string' },
      templates: { type: 'array', items: { type: 'string' } },
      severity: { type: 'string' },
      rateLimit: { type: 'number' },
    },
    required: ['target'],
  },
  execute: async (params: any) => callBridge('kali.nuclei', params),
}

export const raphaelKaliSqlmapTool: Tool = {
  name: 'raphael_kali_sqlmap',
  description: 'Run SQLMap for SQL injection',
  parameters: {
    type: 'object',
    properties: {
      url: { type: 'string' },
      args: { type: 'string' },
    },
    required: ['url'],
  },
  execute: async (params: any) => callBridge('kali.sqlmap', params),
}

export const raphaelKaliHashcatTool: Tool = {
  name: 'raphael_kali_hashcat',
  description: 'Run Hashcat for password cracking',
  parameters: {
    type: 'object',
    properties: {
      args: { type: 'string' },
    },
  },
  execute: async (params: any) => callBridge('kali.hashcat', params),
}

export const raphaelKaliImpacketTool: Tool = {
  name: 'raphael_kali_impacket',
  description: 'Run Impacket script',
  parameters: {
    type: 'object',
    properties: {
      script: { type: 'string' },
      args: { type: 'string' },
    },
    required: ['script'],
  },
  execute: async (params: any) => callBridge('kali.impacket', params),
}

export const raphaelKaliListToolsTool: Tool = {
  name: 'raphael_kali_list_tools',
  description: 'List all available Kali tools',
  parameters: { type: 'object', properties: {} },
  execute: async () => callBridge('kali.list_tools', {}),
}

export const raphaelHarvesterCycleTool: Tool = {
  name: 'raphael_harvester_cycle',
  description: 'Run threat intelligence harvest cycle (CVEs, PoCs, techniques)',
  parameters: {
    type: 'object',
    properties: {
      target: { type: 'string' },
    },
  },
  execute: async (params: any) => callBridge('harvester.run_cycle', params),
}

export const raphaelHarvesterSearchTechniquesTool: Tool = {
  name: 'raphael_harvester_search_techniques',
  description: 'Search harvested ATT&CK techniques',
  parameters: {
    type: 'object',
    properties: {
      query: { type: 'string' },
      category: { type: 'string' },
    },
    required: ['query'],
  },
  execute: async (params: any) => callBridge('harvester.search_techniques', params),
}

export const raphaelHarvesterGetCVEsTool: Tool = {
  name: 'raphael_harvester_get_cves',
  description: 'Get recent CVEs',
  parameters: {
    type: 'object',
    properties: {
      keyword: { type: 'string' },
      days: { type: 'number' },
    },
  },
  execute: async (params: any) => callBridge('harvester.get_cves', params),
}

export const raphaelBrainAnalyticsTool: Tool = {
  name: 'raphael_brain_analytics',
  description: 'Get neural brain analytics and strategy performance',
  parameters: { type: 'object', properties: {} },
  execute: async () => callBridge('brain.analytics', {}),
}

export const raphaelBrainMemoryRecallTool: Tool = {
  name: 'raphael_brain_memory_recall',
  description: 'Query neural memory (episodic or semantic)',
  parameters: {
    type: 'object',
    properties: {
      query: { type: 'string' },
      type: { type: 'string', enum: ['episodic', 'semantic'] },
      limit: { type: 'number' },
    },
    required: ['query'],
  },
  execute: async (params: any) => callBridge('brain.memory_recall', params),
}

export const raphaelBrainMemoryStoreTool: Tool = {
  name: 'raphael_brain_memory_store',
  description: 'Store data in neural memory',
  parameters: {
    type: 'object',
    properties: {
      key: { type: 'string' },
      value: { type: 'object' },
      type: { type: 'string', enum: ['episodic', 'semantic'] },
    },
    required: ['key', 'value'],
  },
  execute: async (params: any) => callBridge('brain.memory_store', params),
}

export const raphaelConductorCallTool: Tool = {
  name: 'raphael_conductor_call',
  description: 'Route prompt through Conductor (safety-filtered model routing)',
  parameters: {
    type: 'object',
    properties: {
      prompt: { type: 'string' },
      model: { type: 'string' },
      category: { type: 'string' },
    },
    required: ['prompt'],
  },
  execute: async (params: any) => callBridge('conductor.call', params),
}

export const raphaelConductorSelectStrategyTool: Tool = {
  name: 'raphael_conductor_select_strategy',
  description: 'Select RL strategy based on context and findings',
  parameters: {
    type: 'object',
    properties: {
      context: { type: 'string' },
      findings: { type: 'array', items: { type: 'object' } },
    },
    required: ['context', 'findings'],
  },
  execute: async (params: any) => callBridge('conductor.select_strategy', params),
}

export const raphaelModelCallTool: Tool = {
  name: 'raphael_model_call',
  description: 'Direct model call with persona override',
  parameters: {
    type: 'object',
    properties: {
      model: { type: 'string' },
      messages: { type: 'array', items: { type: 'object' } },
      systemOverride: { type: 'string' },
    },
    required: ['model', 'messages'],
  },
  execute: async (params: any) => callBridge('model.call', params),
}

export const raphaelPersonaSetTool: Tool = {
  name: 'raphael_persona_set',
  description: 'Set active persona',
  parameters: {
    type: 'object',
    properties: {
      persona: { type: 'string', enum: ['stealth', 'aggressive', 'z3r0', 'blackhat', 'redteam'] },
    },
    required: ['persona'],
  },
  execute: async (params: any) => callBridge('persona.set', params),
}

export const raphaelPersonaResolveTool: Tool = {
  name: 'raphael_persona_resolve',
  description: 'Resolve persona override',
  parameters: {
    type: 'object',
    properties: {
      persona: { type: 'string' },
    },
    required: ['persona'],
  },
  execute: async (params: any) => callBridge('persona.resolve', params),
}

export const raphaelTargetSetTool: Tool = {
  name: 'raphael_target_set',
  description: 'Set target for operations',
  parameters: {
    type: 'object',
    properties: {
      target: { type: 'string' },
    },
    required: ['target'],
  },
  execute: async (params: any) => callBridge('target.set', params),
}

export const raphaelTargetProfileTool: Tool = {
  name: 'raphael_target_profile',
  description: 'Profile target for intelligence gathering',
  parameters: {
    type: 'object',
    properties: {
      target: { type: 'string' },
    },
    required: ['target'],
  },
  execute: async (params: any) => callBridge('target.profile', params),
}

export const raphaelScopeSetTool: Tool = {
  name: 'raphael_scope_set',
  description: 'Set scope for operations',
  parameters: {
    type: 'object',
    properties: {
      scope: { type: 'object' },
    },
    required: ['scope'],
  },
  execute: async (params: any) => callBridge('scope.set', params),
}

export const raphaelTools = [
  // Modes
  raphaelAutonomousTool,
  raphaelCommunityTool,
  raphaelDebateTool,
  raphaelDeepResearchTool,
  raphaelScanTool,
  // Agents
  raphaelReconTool,
  raphaelExploitTool,
  raphaelPostExTool,
  raphaelEngageTool,
  // C2
  raphaelC2BuildImplantTool,
  raphaelC2DeployImplantTool,
  raphaelC2ListBeaconsTool,
  raphaelC2TaskBeaconTool,
  raphaelC2SliverConnectTool,
  // Exploit
  raphaelExploitGenerateTool,
  raphaelExploitRelayChainTool,
  raphaelExploitPayloadDbTool,
  // Kali
  raphaelKaliRunTool,
  raphaelKaliNucleiTool,
  raphaelKaliSqlmapTool,
  raphaelKaliHashcatTool,
  raphaelKaliImpacketTool,
  raphaelKaliListToolsTool,
  // Harvester
  raphaelHarvesterCycleTool,
  raphaelHarvesterSearchTechniquesTool,
  raphaelHarvesterGetCVEsTool,
  // Brain
  raphaelBrainAnalyticsTool,
  raphaelBrainMemoryRecallTool,
  raphaelBrainMemoryStoreTool,
  // Conductor
  raphaelConductorCallTool,
  raphaelConductorSelectStrategyTool,
  // Models/Personas
  raphaelModelCallTool,
  raphaelPersonaSetTool,
  raphaelPersonaResolveTool,
  // Target/Scope
  raphaelTargetSetTool,
  raphaelTargetProfileTool,
  raphaelScopeSetTool,
]