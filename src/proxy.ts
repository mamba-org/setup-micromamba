/**
 * This file is taken from
 * https://github.com/TooTallNate/proxy-agents/blob/main/packages/proxy-agent/src/index.ts.
 * It is stripped to not include proxies for SOCKS and PAC which are not needed.
 */
import * as http from 'http'
import * as https from 'https'
import LRUCache from 'lru-cache'
import type { AgentConnectOpts } from 'agent-base'
import { Agent } from 'agent-base'
import createDebug from 'debug'
import { getProxyForUrl as envGetProxyForUrl } from 'proxy-from-env'
import type { HttpProxyAgentOptions } from 'http-proxy-agent'
import { HttpProxyAgent } from 'http-proxy-agent'
import type { HttpsProxyAgentOptions } from 'https-proxy-agent'
import { HttpsProxyAgent } from 'https-proxy-agent'

const debug = createDebug('proxy-agent')

const PROTOCOLS = [...HttpProxyAgent.protocols] as const

type ValidProtocol = (typeof PROTOCOLS)[number]

type AgentConstructor = new (...args: never[]) => Agent

type GetProxyForUrlCallback = (url: string) => string

/**
 * Supported proxy types.
 */
export const proxies: {
  [P in ValidProtocol]: [AgentConstructor, AgentConstructor]
} = {
  http: [HttpProxyAgent, HttpsProxyAgent],
  https: [HttpProxyAgent, HttpsProxyAgent]
}

function isValidProtocol(v: string): v is ValidProtocol {
  return (PROTOCOLS as readonly string[]).includes(v)
}

export type ProxyAgentOptions = HttpProxyAgentOptions<''> & HttpsProxyAgentOptions<''>

/**
 * Uses the appropriate `Agent` subclass based off of the "proxy"
 * environment variables that are currently set.
 *
 * An LRU cache is used, to prevent unnecessary creation of proxy
 * `http.Agent` instances.
 */
export class ProxyAgent extends Agent {
  /**
   * Cache for `Agent` instances.
   */
  cache = new LRUCache<string, Agent>({ max: 20 })

  connectOpts?: ProxyAgentOptions
  httpAgent: http.Agent
  httpsAgent: http.Agent
  getProxyForUrl: GetProxyForUrlCallback

  constructor(opts?: ProxyAgentOptions) {
    super(opts)
    debug('Creating new ProxyAgent instance: %o', opts)
    this.connectOpts = opts
    this.httpAgent = new http.Agent(opts)
    this.httpsAgent = new https.Agent(opts as https.AgentOptions)
    this.getProxyForUrl = envGetProxyForUrl
  }

  async connect(req: http.ClientRequest, opts: AgentConnectOpts): Promise<http.Agent> {
    const { secureEndpoint } = opts
    const protocol = secureEndpoint ? 'https:' : 'http:'
    const host = req.getHeader('host')
    const url = new URL(req.path, `${protocol}//${host}`).href
    const proxy = this.getProxyForUrl(url)

    if (!proxy) {
      debug('Proxy not enabled for URL: %o', url)
      return secureEndpoint ? this.httpsAgent : this.httpAgent
    }

    debug('Request URL: %o', url)
    debug('Proxy URL: %o', proxy)

    // attempt to get a cached `http.Agent` instance first
    const cacheKey = `${protocol}+${proxy}`
    let agent = this.cache.get(cacheKey)
    if (!agent) {
      const proxyUrl = new URL(proxy)
      const proxyProto = proxyUrl.protocol.replace(':', '')
      if (!isValidProtocol(proxyProto)) {
        throw new Error(`Unsupported protocol for proxy URL: ${proxy}`)
      }
      const Ctor = proxies[proxyProto][secureEndpoint ? 1 : 0]
      // @ts-expect-error meh…
      agent = new Ctor(proxy, this.connectOpts)
      this.cache.set(cacheKey, agent)
    } else {
      debug('Cache hit for proxy URL: %o', proxy)
    }

    return agent
  }

  destroy(): void {
    for (const agent of this.cache.values()) {
      agent.destroy()
    }
    super.destroy()
  }
}
