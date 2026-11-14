import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { bytes, clean, sections, setPath, uptime, dashboardUrl } from './model'

describe('configuration edits', () => {
  it('uses a reachable panel address for wildcard binds, IPv6 and disabled panels', () => {
    expect(
      dashboardUrl(
        { enabled: true, listen_address: '0.0.0.0:9900' },
        'http://192.168.1.2:9800',
      ),
    ).toBe('http://192.168.1.2:9900')
    expect(
      dashboardUrl(
        { enabled: true, listen_address: '[::]:9900' },
        'http://[::1]:9800',
      ),
    ).toBe('http://[::1]:9900')
    expect(
      dashboardUrl(
        { enabled: true, listen_address: '127.0.0.1:9900' },
        'http://localhost:9800',
      ),
    ).toBe('http://localhost:9900')
    expect(
      dashboardUrl(
        { enabled: false, listen_address: '127.0.0.1:9900' },
        'http://localhost:9800',
      ),
    ).toBeNull()
  })
  it('keeps the original config untouched, including nullable paths', () => {
    const original = {
      logging: { directory: null, max_files: 7 },
      dns_proxy: { nameservers: ['1.1.1.1:53'] },
    }
    const next = setPath(original, ['logging', 'directory'], './logs')
    expect(original.logging.directory).toBeNull()
    expect(next.logging).toEqual({ directory: './logs', max_files: 7 })
    expect(next.dns_proxy).toEqual(original.dns_proxy)
  })
  it('removes unfinished list rows without losing optional fields or false', () => {
    expect(
      clean({
        servers: ['https://1.1.1.1/dns-query', '', ' '],
        enabled: false,
        path: null,
      }),
    ).toEqual({
      servers: ['https://1.1.1.1/dns-query'],
      enabled: false,
      path: null,
    })
  })
  it('assigns every top-level current client setting exactly once', () => {
    const keys = sections.flatMap((section) => [...section.keys])
    expect(new Set(keys).size).toBe(keys.length)
    const source = readFileSync(
      new URL('../../crates/rvpn-client/src/config.rs', import.meta.url),
      'utf8',
    )
    const definition = source.slice(
      source.indexOf('pub struct ClientConfig {'),
      source.indexOf('impl Default for ClientConfig'),
    )
    const rustKeys = [...definition.matchAll(/pub (\w+):/g)].map((match) =>
      match[1] === 'extra_servers' ? 'server' : match[1],
    )
    expect([...keys].sort()).toEqual(rustKeys.sort())
  })
})
describe('statistics formatting', () => {
  it('shows real zero and scaled byte counts', () => {
    expect(bytes(0)).toBe('0 B')
    expect(bytes(1048576)).toBe('1.0 MB')
  })
  it('does not wrap uptime at 24 hours', () => {
    expect(uptime(90061)).toBe('25:01:01')
  })
})
