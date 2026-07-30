import type { Tool } from '../tools.js';
import { getRaphaelBridge } from '../services/raphael-bridge.js';

export const raphaelTools: Tool[] = [
  {
    name: 'raphael_autonomous',
    description: 'Launch full autonomous operation against a target',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Target IP, domain, or CIDR' },
        phases: { type: 'array', items: { type: 'string' }, description: 'Phases to run' },
        persona: { type: 'string', enum: ['stealth', 'aggressive', 'z3r0', 'blackhat', 'redteam'] },
      },
      required: ['target'],
    },
    handler: async ({ target, phases, persona }) => {
      const bridge = await getRaphaelBridge();
      return bridge.autonomous(target, { phases, persona });
    },
  },

  {
    name: 'raphael_community',
    description: 'Multi-model collaborative problem solving',
    inputSchema: {
      type: 'object',
      properties: {
        question: { type: 'string' },
        models: { type: 'array', items: { type: 'string' } },
        rounds: { type: 'number' },
      },
      required: ['question'],
    },
    handler: async ({ question, models, rounds }) => {
      const bridge = await getRaphaelBridge();
      return bridge.community(question, { models, rounds });
    },
  },

  {
    name: 'raphael_debate',
    description: 'Adversarial debate between two models with skill evidence',
    inputSchema: {
      type: 'object',
      properties: {
        question: { type: 'string' },
        models: { type: 'array', items: { type: 'string' } },
        rounds: { type: 'number' },
        useSkills: { type: 'boolean' },
      },
      required: ['question'],
    },
    handler: async ({ question, models, rounds, useSkills }) => {
      const bridge = await getRaphaelBridge();
      return bridge.debate(question, { models, rounds, useSkills });
    },
  },

  {
    name: 'raphael_deep_research',
    description: 'Deep research with phased methodology and adversarial verification',
    inputSchema: {
      type: 'object',
      properties: {
        topic: { type: 'string' },
      },
      required: ['topic'],
    },
    handler: async ({ topic }) => {
      const bridge = await getRaphaelBridge();
      return bridge.deepResearch(topic);
    },
  },

  {
    name: 'raphael_kali_run',
    description: 'Execute any Kali Linux tool (300+ available)',
    inputSchema: {
      type: 'object',
      properties: {
        tool: { type: 'string' },
        args: { type: 'string' },
        timeout: { type: 'number' },
      },
      required: ['tool'],
    },
    handler: async ({ tool, args, timeout }) => {
      const bridge = await getRaphaelBridge();
      return bridge.kaliRun(tool, args, timeout);
    },
  },

  {
    name: 'raphael_nuclei',
    description: 'Run Nuclei vulnerability scanner',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string' },
        templates: { type: 'array', items: { type: 'string' } },
        severity: { type: 'string' },
        rateLimit: { type: 'number' },
      },
      required: ['target'],
    },
    handler: async ({ target, templates, severity, rateLimit }) => {
      const bridge = await getRaphaelBridge();
      return bridge.kaliNuclei(target, { templates, severity, rateLimit });
    },
  },

  {
    name: 'raphael_sqlmap',
    description: 'Run SQLMap for SQL injection',
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string' },
        args: { type: 'string' },
      },
      required: ['url'],
    },
    handler: async ({ url, args }) => {
      const bridge = await getRaphaelBridge();
      return bridge.kaliSqlmap(url, args);
    },
  },

  {
    name: 'raphael_harvester_cycle',
    description: 'Run threat intelligence harvest cycle (CVEs, PoCs, techniques)',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string' },
      },
    },
    handler: async ({ target }) => {
      const bridge = await getRaphaelBridge();
      return bridge.harvesterRunCycle(target);
    },
  },

  {
    name: 'raphael_search_techniques',
    description: 'Search harvested ATT&CK techniques',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string' },
        category: { type: 'string' },
      },
      required: ['query'],
    },
    handler: async ({ query, category }) => {
      const bridge = await getRaphaelBridge();
      return bridge.harvesterSearchTechniques(query, category);
    },
  },

  {
    name: 'raphael_c2_build_implant',
    description: 'Build a C2 implant (native, Sliver, or noop)',
    inputSchema: {
      type: 'object',
      properties: {
        config: { type: 'object' },
      },
      required: ['config'],
    },
    handler: async ({ config }) => {
      const bridge = await getRaphaelBridge();
      return bridge.buildImplant(config);
    },
  },

  {
    name: 'raphael_c2_list_beacons',
    description: 'List active C2 beacons',
    inputSchema: { type: 'object', properties: {} },
    handler: async () => {
      const bridge = await getRaphaelBridge();
      return bridge.listBeacons();
    },
  },

  {
    name: 'raphael_exploit_generate',
    description: 'Generate exploit code for a vulnerability type',
    inputSchema: {
      type: 'object',
      properties: {
        vulnType: { type: 'string' },
        targetInfo: { type: 'object' },
      },
      required: ['vulnType', 'targetInfo'],
    },
    handler: async ({ vulnType, targetInfo }) => {
      const bridge = await getRaphaelBridge();
      return bridge.generateExploit(vulnType, targetInfo);
    },
  },

  {
    name: 'raphael_brain_analytics',
    description: 'Get neural brain analytics and strategy performance',
    inputSchema: { type: 'object', properties: {} },
    handler: async () => {
      const bridge = await getRaphaelBridge();
      return bridge.brainAnalytics();
    },
  },

  {
    name: 'raphael_brain_memory_recall',
    description: 'Query neural memory (episodic or semantic)',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string' },
        type: { type: 'string', enum: ['episodic', 'semantic'] },
        limit: { type: 'number' },
      },
      required: ['query'],
    },
    handler: async ({ query, type, limit }) => {
      const bridge = await getRaphaelBridge();
      return bridge.brainMemoryRecall(query, type, limit);
    },
  },

  {
    name: 'raphael_conductor_call',
    description: 'Route prompt through Conductor (safety-filtered model routing)',
    inputSchema: {
      type: 'object',
      properties: {
        prompt: { type: 'string' },
        model: { type: 'string' },
        category: { type: 'string' },
      },
      required: ['prompt'],
    },
    handler: async ({ prompt, model, category }) => {
      const bridge = await getRaphaelBridge();
      return bridge.conductorCall(prompt, model, category);
    },
  },
];