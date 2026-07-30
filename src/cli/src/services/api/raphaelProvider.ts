import Anthropic from '@anthropic-ai/sdk'
import type { ClientOptions } from '@anthropic-ai/sdk'

export interface RaphaelConfig {
  orchestratorUrl?: string
  apiKey?: string
  target?: string
  mode?: string
  persona?: string
  opsec?: any
}

async function* streamSSE(response: Response) {
  const reader = response.body?.getReader()
  if (!reader) return

  const decoder = new TextDecoder()
  let buffer = ''

  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += new TextDecoder().decode(value, { stream: true })
    const lines = buffer.split('\n')
    buffer = lines.pop() || ''

    for (const line of lines) {
      if (line.startsWith('data: ')) {
        try {
          const data = JSON.parse(line.slice(6))
          yield data
        } catch {
          // ignore malformed JSON
        }
      }
    }
  }
}

export function createRaphaelClient(options: {
  defaultHeaders?: Record<string, string>
  maxRetries?: number
  timeout?: number
  reasoningEffort?: 'low' | 'medium' | 'high' | 'xhigh'
  providerOverride?: { model: string; baseURL: string; apiKey: string }
}) {
  const orchestratorUrl = process.env.RAPHAEL_ORCHESTRATOR_URL || 'http://localhost:8080'
  const apiKey = process.env.RAPHAEL_API_KEY
  const defaultTarget = process.env.RAPHAEL_TARGET
  const defaultMode = process.env.RAPHAEL_MODE || 'autonomous'
  const defaultPersona = process.env.RAPHAEL_PERSONA || 'stealth'

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(apiKey ? { 'X-API-Key': apiKey } : {}),
    ...options.defaultHeaders,
  }

  const fetchWithTimeout = (url: string, init: RequestInit, timeoutMs: number) => {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), timeoutMs)
    return fetch(url, { ...init, signal: controller.signal }).finally(() => clearTimeout(timeout))
  }

  return {
    messages: {
      create: async (params: any) => {
        const {
          messages,
          tools,
          target = process.env.RAPHAEL_TARGET || defaultTarget,
          mode = process.env.RAPHAEL_MODE || defaultMode,
          persona = process.env.RAPHAEL_PERSONA || defaultPersona,
          opsec,
        } = params

        // Build the payload for the orchestrator
        const payload = {
          messages: messages.map((m: any) => ({
            role: m.role,
            content: typeof m.content === 'string' ? m.content : JSON.stringify(m.content),
          })),
          tools: tools?.map((t: any) => ({
            name: t.name,
            description: t.description,
            parameters: t.input_schema || t.parameters,
          })),
          target,
          mode,
          persona,
          opsec: { ...opsec, ...params.opsec },
        }

        const response = await fetchWithTimeout(
          `${process.env.RAPHAEL_ORCHESTRATOR_URL}/api/agent/execute`,
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              ...(process.env.RAPHAEL_API_KEY ? { 'X-API-Key': process.env.RAPHAEL_API_KEY } : {}),
            },
            body: JSON.stringify(payload),
          },
          600000 // 10 minute timeout
        )

        if (!response.ok) {
          const error = await response.text()
          throw new Error(`Orchestrator error: ${response.status} - ${error}`)
        }

        // For now, return a simple text response
        // In production, this would stream SSE events
        const data = await response.json()

        return {
          id: data.id || `msg_${Date.now()}`,
          type: 'message',
          role: 'assistant',
          content: [{ type: 'text', text: data.result || data.text || JSON.stringify(data) }],
          model: params.model || 'raphael',
          stop_reason: 'end_turn',
          usage: { input_tokens: 0, output_tokens: 0 },
        }
      },
    },
    beta: {
      messages: {
        create: async (params: any, options?: { stream?: boolean }) => {
          if (options?.stream) {
            // Return async generator for streaming
            return (async function* () {
              const payload = {
                messages: params.messages.map((m: any) => ({
                  role: m.role,
                  content: typeof m.content === 'string' ? m.content : JSON.stringify(m.content),
                })),
                tools: params.tools?.map((t: any) => ({
                  name: t.name,
                  description: t.description,
                  parameters: t.input_schema || t.parameters,
                })),
                target: params.target || process.env.RAPHAEL_TARGET,
                mode: params.mode || process.env.RAPHAEL_MODE || 'autonomous',
                persona: params.persona || process.env.RAPHAEL_PERSONA || 'stealth',
                opsec: params.opsec,
              }

              const response = await fetchWithTimeout(
                `${process.env.RAPHAEL_ORCHESTRATOR_URL}/api/agent/execute`,
                {
                  method: 'POST',
                  headers: {
                    'Content-Type': 'application/json',
                    ...(process.env.RAPHAEL_API_KEY ? { 'X-API-Key': process.env.RAPHAEL_API_KEY } : {}),
                  },
                  body: JSON.stringify(payload),
                },
                600000
              )

              if (!response.ok) {
                const error = await response.text()
                throw new Error(`Orchestrator error: ${response.status} - ${error}`)
              }

              yield {
                type: 'message_start',
                message: {
                  id: `msg_${Date.now()}`,
                  type: 'message',
                  role: 'assistant',
                  content: [],
                  model: params.model || 'raphael',
                  stop_reason: null,
                  stop_sequence: null,
                  usage: { input_tokens: 0, output_tokens: 0 },
                },
              }

              for await (const event of streamSSE(response)) {
                if (event.type === 'text') {
                  yield {
                    type: 'content_block_delta',
                    index: 0,
                    delta: { type: 'text_delta', text: event.text },
                  }
                } else if (event.type === 'tool_call') {
                  yield {
                    type: 'content_block_start',
                    index: 0,
                    content_block: { type: 'tool_use', id: event.id, name: event.tool, input: {} },
                  }
                  yield {
                    type: 'content_block_delta',
                    index: 0,
                    delta: { type: 'input_json_delta', partial_json: JSON.stringify(event.args) },
                  }
                  yield {
                    type: 'content_block_stop',
                    index: 0,
                  }
                }
              }

              yield {
                type: 'message_delta',
                delta: { stop_reason: 'end_turn', stop_sequence: null },
                usage: { input_tokens: 0, output_tokens: 0 },
              }
              yield { type: 'message_stop' }
            })()
          } else {
            // Non-streaming - same as create
            return (await import('./raphaelProvider.js')).messages.create(params)
          }
        },
      },
    },
  }
}

export function createRaphaelClient(options: {
  defaultHeaders?: Record<string, string>
  maxRetries?: number
  timeout?: number
  reasoningEffort?: 'low' | 'medium' | 'high' | 'xhigh'
  providerOverride?: { model: string; baseURL: string; apiKey: string }
}): any {
  return createRaphaelClient(options)
}