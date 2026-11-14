export type Config = Record<string, unknown>
export type Session = {
  config: Config
  revision: string
  path: string
  restart_required: boolean
  pending_changes?: boolean
  access_allowed?: boolean
  version: string
  runtime: {
    dashboard?: { enabled: boolean; listen_address: string }
    server_address: string
    tun: boolean
    socks5: string
    http_proxy: string
    dns_proxy: string
  }
}

export function dashboardUrl(
  settings: { enabled: boolean; listen_address: string },
  currentAddress: string,
) {
  if (!settings.enabled) return null
  const current = new URL(currentAddress)
  const next = new URL(`http://${settings.listen_address}`)
  if (
    ['0.0.0.0', '[::]'].includes(next.hostname) ||
    (['127.0.0.1', '[::1]'].includes(next.hostname) &&
      current.hostname === 'localhost')
  )
    next.hostname = current.hostname
  return next.origin
}
export type Stats = {
  uptime_secs: number
  bucket_secs: number
  runtime_error?: string | null
  counters: Record<string, number>
  buckets: { ts: number; bytes_up: number; bytes_down: number }[]
}

export function clean(value: unknown): unknown {
  if (Array.isArray(value))
    return value
      .filter((v) => typeof v !== 'string' || v.trim() !== '')
      .map(clean)
  if (value && typeof value === 'object')
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, clean(v)]),
    )
  return value
}
export function setPath(
  config: Config,
  path: string[],
  value: unknown,
): Config {
  const next = structuredClone(config)
  let node: Record<string, unknown> = next
  for (const key of path.slice(0, -1))
    node = node[key] as Record<string, unknown>
  node[path.at(-1)!] = value
  return next
}
export function bytes(value = 0) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let index = 0
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024
    index++
  }
  return `${value.toFixed(index === 0 ? 0 : 1)} ${units[index]}`
}
export function uptime(seconds = 0) {
  return `${Math.floor(seconds / 3600)
    .toString()
    .padStart(2, '0')}:${Math.floor((seconds % 3600) / 60)
    .toString()
    .padStart(2, '0')}:${Math.floor(seconds % 60)
    .toString()
    .padStart(2, '0')}`
}

export const sections = [
  {
    id: 'connection',
    title: '连接与节点',
    sub: '连接端点、TLS 指纹与多节点路由',
    icon: 'globe',
    keys: [
      'server_address',
      'sni_hostname',
      'tls_fingerprint',
      'server_public_key',
      'identity_key_file',
      'prekey_bundle',
      'data_dir',
      'server',
      'routing',
    ],
  },
  {
    id: 'proxy',
    title: '本地代理',
    sub: 'SOCKS5 与 HTTP 代理监听及认证',
    icon: 'network',
    keys: ['socks5', 'http_proxy'],
  },
  {
    id: 'dns',
    title: 'DNS 与网络',
    sub: 'DoH 上游、DNS 缓存与 IP 协议',
    icon: 'radio',
    keys: ['dns_proxy', 'network'],
  },
  {
    id: 'split',
    title: '分流规则',
    sub: '直连地区、域名规则与广告拦截',
    icon: 'route',
    keys: ['split_tunnel'],
  },
  {
    id: 'tun',
    title: 'TUN 网络',
    sub: '虚拟网卡、路由与 MTU',
    icon: 'layers',
    keys: ['tun'],
  },
  {
    id: 'security',
    title: '身份与安全',
    sub: '服务器指纹验证与首次信任策略',
    icon: 'shield',
    keys: ['server_identity'],
  },
  {
    id: 'system',
    title: '程序设置',
    sub: '日志、性能和控制面板访问',
    icon: 'settings',
    keys: ['logging', 'performance', 'dashboard'],
  },
] as const

export const labels: Record<string, string> = {
  server_address: '服务器地址',
  sni_hostname: 'TLS SNI 主机名',
  tls_fingerprint: 'TLS 浏览器指纹',
  server_public_key: '服务器公钥',
  identity_key_file: '客户端身份密钥文件',
  prekey_bundle: '服务器预密钥包',
  data_dir: '数据目录',
  server: '附加服务器',
  routing: '按服务器分配路由',
  socks5: 'SOCKS5 代理',
  http_proxy: 'HTTP / HTTPS 代理',
  dns_proxy: 'DNS 代理',
  network: '网络设置',
  split_tunnel: '分流设置',
  tun: 'TUN 虚拟网卡',
  server_identity: '服务器身份验证',
  logging: '文件日志',
  performance: '性能设置',
  dashboard: '控制面板',
  enabled: '启用',
  listen_address: '监听地址',
  udp_associate: 'UDP 转发',
  auth_enabled: '代理身份认证',
  auth_username: '用户名',
  auth_password: '密码',
  multiplex: '复用兼容开关',
  mode: '隧道连接模式',
  mux_path: '复用 WebSocket 路径',
  pool_size: '初始连接池大小',
  pool_max: '最大连接池大小',
  max_flows_per_conn: '单连接最大流数',
  rotate_after_secs: '连接轮换间隔（秒）',
  rotate_after_mb: '连接轮换流量（MB）',
  rotation_jitter: '轮换抖动比例',
  nameservers: 'DNS 上游',
  ipv6_enabled: '启用 IPv6',
  prefer_ipv4: '优先 IPv4',
  dns_cache_enabled: 'DNS 缓存',
  dns_cache_ttl: '缓存 TTL（秒）',
  dns_cache_size: '最大缓存条数',
  dns_servers: 'DNS 服务器',
  interface_name: '网卡名称',
  ip_address: '旧版固定 IP（现由服务器分配）',
  routes: '路由网段',
  mtu: 'MTU',
  fingerprint: '固定身份指纹',
  trust_on_first_use: '首次使用时信任',
  known_hosts_file: '已知服务器文件',
  strict: '严格验证指纹',
  strict_mode: '拒绝未知服务器',
  file_enabled: '写入日志文件',
  directory: '日志目录',
  level: '日志级别',
  max_files: '保留日志份数',
  worker_threads: '工作线程',
  crypto_worker_count: '加密工作线程',
  recv_buffer_size: '接收缓冲区（字节）',
  send_buffer_size: '发送缓冲区（字节）',
  allow_cidrs: '允许访问的网段',
  bypassNetworksFile: '直连 IP 列表文件',
  bypassDomainsFile: '直连域名文件',
  countryDomainsFile: '地区域名文件',
  tunnelNetworksFile: '隧道 IP 列表文件',
  tunnelDomainsFile: '隧道域名文件',
  autoReloadInterval: '规则重载间隔（秒）',
  builtinBypassCountries: '内置直连地区',
  blockAds: '广告拦截',
  adBlockFile: '自定义广告规则文件',
  bypassNetworks: '附加直连网段',
  countryIpsFile: '地区 IP 数据文件',
  name: '节点名称',
  address: '节点地址',
  domains: '域名规则',
  ips: 'IP / CIDR 规则',
}
export const hints: Record<string, string> = {
  file_enabled: '客户端写文件时，控制台仅保留管理页面访问提示。',
  server_address: '支持 ws:// 或 wss://，包含 WebSocket 路径。',
  prekey_bundle: '使用服务端生成的公开 prekey-bundle.json。',
  nameservers: '每行一个 UDP 地址或 DoH HTTPS URL，可混合使用。',
  directory: '留空时写在程序目录；./logs 相对于配置文件目录。',
  mode: '留空时由复用兼容开关决定；pooled 使用连接池。',
  allow_cidrs:
    '允许的设备可修改全部配置。保存后立即更新权限，移除当前设备会断开面板连接。',
  identity_key_file: '文件不存在时自动生成。相对路径基于配置文件目录。',
  builtinBypassCountries: '每行一个地区代码，例如 CN、HK。',
  dashboard: '地址更改后自动切换；关闭面板将立即停止 Web 访问。',
  logging: '保存后立即切换日志级别和文件设置，不中断代理连接。',
}
export const options: Record<string, string[]> = {
  tls_fingerprint: [
    'chrome',
    'firefox',
    'safari',
    'ios',
    'android',
    'edge',
    'none',
  ],
  mode: ['', 'legacy', 'multiplex', 'pooled'],
  level: ['off', 'error', 'warn', 'info', 'debug', 'trace'],
}
