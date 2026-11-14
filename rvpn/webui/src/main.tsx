import React, { useEffect, useId, useState } from 'react'
import { createRoot } from 'react-dom/client'
import {
  Activity,
  ArrowDownLeft,
  ArrowUpRight,
  Check,
  ChevronRight,
  CircleHelp,
  Clock3,
  ExternalLink,
  Globe2,
  Layers3,
  LayoutDashboard,
  Network,
  Plus,
  Radio,
  RefreshCw,
  Route,
  Save,
  Search,
  Settings2,
  ShieldCheck,
  SlidersHorizontal,
  Wifi,
  X,
} from 'lucide-react'
import '@fontsource/inter/latin-600.css'
import '@fontsource/inter/latin-800.css'
import {
  bytes,
  clean,
  dashboardUrl,
  hints,
  labels,
  options,
  sections,
  setPath,
  uptime,
} from './model'
import type { Config, Session, Stats } from './model'
import { useControl } from './useControl'
import './style.css'

const icons = {
  globe: Globe2,
  network: Network,
  radio: Radio,
  route: Route,
  layers: Layers3,
  shield: ShieldCheck,
  settings: Settings2,
}

function Field({
  name,
  value,
  onChange,
}: {
  name: string
  value: unknown
  onChange: (value: unknown) => void
}) {
  const id = useId()
  const caption = labels[name] || name
  if (typeof value === 'boolean')
    return (
      <div className="field switch-field">
        <label htmlFor={id}>
          <strong>{caption}</strong>
          <span>{name}</span>
        </label>
        <button
          id={id}
          type="button"
          role="switch"
          aria-label={caption}
          aria-checked={value}
          className={`switch ${value ? 'on' : ''}`}
          onClick={() => onChange(!value)}
        >
          <i />
        </button>
      </div>
    )
  if (value && typeof value === 'object' && !Array.isArray(value))
    return (
      <fieldset className="nested">
        <legend>{caption}</legend>
        <div className="fields">
          {Object.entries(value).map(([key, v]) => (
            <Field
              key={key}
              name={key}
              value={v}
              onChange={(next) => onChange({ ...value, [key]: next })}
            />
          ))}
        </div>
      </fieldset>
    )
  const nullable =
    value === null ||
    [
      'sni_hostname',
      'server_public_key',
      'prekey_bundle',
      'auth_username',
      'auth_password',
      'interface_name',
      'ip_address',
      'fingerprint',
      'directory',
      'bypassNetworksFile',
      'bypassDomainsFile',
      'countryDomainsFile',
      'tunnelNetworksFile',
      'tunnelDomainsFile',
      'adBlockFile',
      'countryIpsFile',
    ].includes(name)
  const list = Array.isArray(value)
  return (
    <div className={`field ${list ? 'wide' : ''}`}>
      <label htmlFor={id}>
        {caption}
        <small>{name}</small>
      </label>
      {options[name] ? (
        <select
          id={id}
          value={String(value ?? '')}
          onChange={(e) => onChange(e.target.value || null)}
        >
          {options[name].map((option) => (
            <option key={option} value={option}>
              {option || '自动 / 使用兼容设置'}
            </option>
          ))}
        </select>
      ) : list ? (
        <textarea
          id={id}
          rows={Math.min(6, Math.max(3, value.length + 1))}
          placeholder="每行一条"
          value={value.join('\n')}
          onChange={(e) => onChange(e.target.value.split('\n'))}
        />
      ) : (
        <input
          id={id}
          type={
            typeof value === 'number'
              ? 'number'
              : name.includes('password')
                ? 'password'
                : 'text'
          }
          step={
            name === 'rotation_jitter'
              ? '0.01'
              : typeof value === 'number'
                ? '1'
                : undefined
          }
          value={String(value ?? '')}
          placeholder={nullable ? '未设置（可选）' : undefined}
          autoComplete="off"
          onChange={(e) =>
            onChange(
              typeof value === 'number'
                ? e.target.value === ''
                  ? 0
                  : Number(e.target.value)
                : e.target.value || (nullable ? null : ''),
            )
          }
        />
      )}
      {hints[name] && <p className="field-hint">{hints[name]}</p>}
      {nullable && <span className="optional">可选</span>}
    </div>
  )
}

function ServerEditor({
  value,
  onChange,
}: {
  value: unknown[]
  onChange: (value: unknown[]) => void
}) {
  return (
    <div className="wide">
      <div className="editor-toolbar">
        <span>
          附加服务器 <em>{value.length}</em>
        </span>
        <button
          className="button secondary small"
          onClick={() =>
            onChange([
              ...value,
              {
                name: '',
                address: 'wss://',
                prekey_bundle: '',
                sni_hostname: null,
                fingerprint: null,
              },
            ])
          }
        >
          <Plus size={14} />
          添加节点
        </button>
      </div>
      {value.length === 0 && (
        <div className="empty-row">
          当前使用主服务器。添加节点后，可按域名或 IP 分配流量。
        </div>
      )}
      {value.map((entry, index) => (
        <div className="entry" key={index}>
          <div className="entry-heading">
            <span>节点 {String(index + 1).padStart(2, '0')}</span>
            <button
              className="icon-button"
              aria-label={`移除节点 ${index + 1}`}
              onClick={() => onChange(value.filter((_, i) => i !== index))}
            >
              <X size={16} />
            </button>
          </div>
          <div className="fields">
            {Object.entries(entry as Config).map(([name, v]) => (
              <Field
                key={name}
                name={name}
                value={v}
                onChange={(next) =>
                  onChange(
                    value.map((item, i) =>
                      i === index
                        ? { ...(item as Config), [name]: next }
                        : item,
                    ),
                  )
                }
              />
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

function RoutingEditor({
  value,
  onChange,
}: {
  value: Config
  onChange: (value: Config) => void
}) {
  const [name, setName] = useState('')
  return (
    <div className="wide">
      <div className="editor-toolbar">
        <span>按服务器分配路由</span>
        <div className="add-rule">
          <input
            aria-label="路由目标节点名"
            placeholder="目标节点名 / default"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <button
            className="button secondary small"
            disabled={!name.trim() || name.trim() in value}
            onClick={() => {
              onChange({ ...value, [name.trim()]: { domains: [], ips: [] } })
              setName('')
            }}
          >
            <Plus size={14} />
            添加
          </button>
        </div>
      </div>
      {!Object.keys(value).length && (
        <div className="empty-row">未匹配规则的连接使用主服务器。</div>
      )}
      {Object.entries(value).map(([key, rule]) => (
        <div className="entry" key={key}>
          <div className="entry-heading">
            <span>{key}</span>
            <button
              className="icon-button"
              aria-label={`移除路由 ${key}`}
              onClick={() =>
                onChange(
                  Object.fromEntries(
                    Object.entries(value).filter(([k]) => k !== key),
                  ),
                )
              }
            >
              <X size={16} />
            </button>
          </div>
          <div className="fields">
            {Object.entries(rule as Config).map(([field, v]) => (
              <Field
                key={field}
                name={field}
                value={v}
                onChange={(next) =>
                  onChange({
                    ...value,
                    [key]: { ...(rule as Config), [field]: next },
                  })
                }
              />
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

function TrafficChart({ stats }: { stats: Stats | null }) {
  const buckets = stats?.buckets.slice(-60) || []
  const maximum = Math.max(
    1,
    ...buckets.flatMap((b) => [b.bytes_up, b.bytes_down]),
  )
  const path = (key: 'bytes_up' | 'bytes_down') =>
    buckets
      .map(
        (b, i) =>
          `${i === 0 ? 'M' : 'L'}${((i / Math.max(1, buckets.length - 1)) * 800).toFixed(1)},${(150 - (b[key] / maximum) * 125).toFixed(1)}`,
      )
      .join(' ')
  return (
    <div className="traffic-chart">
      <div className="chart-axis">
        <span>{bytes(maximum / 5)}/s</span>
        <span>{bytes(maximum / 10)}/s</span>
        <span>0 B/s</span>
      </div>
      <svg
        role="img"
        aria-label="最近五分钟上传和下载流量"
        viewBox="0 0 800 170"
        preserveAspectRatio="none"
      >
        <defs>
          <linearGradient id="trafficFill" x1="0" y1="0" x2="0" y2="1">
            <stop stopColor="#00b24b" stopOpacity=".22" />
            <stop offset="1" stopColor="#00b24b" stopOpacity="0" />
          </linearGradient>
        </defs>
        {[25, 87, 150].map((y) => (
          <line
            key={y}
            x1="0"
            x2="800"
            y1={y}
            y2={y}
            stroke="#34363b"
            strokeDasharray="4 6"
          />
        ))}
        {buckets.length > 1 && (
          <>
            <path
              d={`${path('bytes_down')} L800,170 L0,170 Z`}
              fill="url(#trafficFill)"
            />
            <path
              d={path('bytes_down')}
              fill="none"
              stroke="#00b24b"
              strokeWidth="2.5"
            />
            <path
              d={path('bytes_up')}
              fill="none"
              stroke="#0075ff"
              strokeWidth="2"
            />
          </>
        )}
        {buckets.length < 2 && (
          <text x="400" y="90" textAnchor="middle" fill="#9aa1b1" fontSize="14">
            等待流量采样，建立连接后自动更新
          </text>
        )}
      </svg>
      <div className="chart-times">
        <span>5 分钟前</span>
        <span>现在</span>
      </div>
    </div>
  )
}

function Overview({
  session,
  stats,
  connected,
  navigate,
}: {
  session: Session | null
  stats: Stats | null
  connected: boolean
  navigate: (page: string) => void
}) {
  const counters = stats?.counters || {}
  const active = Math.max(
    0,
    (counters.conns_accepted || 0) - (counters.conns_completed || 0),
  )
  const latest = stats?.buckets.at(-1)
  return (
    <>
      <section className="hero">
        <div>
          <div className="eyebrow">
            <span className={`dot ${connected ? 'live' : ''}`} />
            {connected ? '客户端已连接' : '客户端未连接'}
          </div>
          <h1>
            你的网络，
            <br />
            由你掌控<span>。</span>
          </h1>
          <p>连接状态、实时流量与每一条规则，尽在此处。</p>
          <button
            className="button primary"
            onClick={() => navigate('connection')}
          >
            管理连接
            <ChevronRight size={16} />
          </button>
        </div>
        <div className="hero-network" aria-hidden="true">
          <div className="orbit orbit-one" />
          <div className="orbit orbit-two" />
          <div className="orbit orbit-three" />
          <div className="network-center">
            <ShieldCheck size={47} strokeWidth={1.5} />
          </div>
          <div className="network-node node-one">
            <Globe2 size={20} />
          </div>
          <div className="network-node node-two">
            <Wifi size={20} />
          </div>
          <div className="network-node node-three">
            <Layers3 size={19} />
          </div>
          <span className="network-tag">DOUBLE RATCHET ENCRYPTION</span>
        </div>
        <div className="hero-status">
          <span>当前网络模式</span>
          <strong>
            {session?.runtime.tun ? 'TUN 全局网络' : 'SOCKS5 代理'}
          </strong>
          <span className="live-label">
            <i />
            端到端加密
          </span>
        </div>
      </section>
      <div className="metrics-grid">
        {[
          {
            label: '实时下载',
            value: `${bytes((latest?.bytes_down || 0) / 5)}`,
            unit: '/s',
            icon: ArrowDownLeft,
            color: 'green',
            sub: `累计 ${bytes(counters.bytes_down)}`,
          },
          {
            label: '实时上传',
            value: bytes((latest?.bytes_up || 0) / 5),
            unit: '/s',
            icon: ArrowUpRight,
            color: 'blue',
            sub: `累计 ${bytes(counters.bytes_up)}`,
          },
          {
            label: '活跃连接',
            value: String(active),
            unit: '',
            icon: Network,
            color: 'blue',
            sub: `已处理 ${counters.conns_accepted || 0} 个连接`,
          },
          {
            label: '运行时长',
            value: uptime(stats?.uptime_secs),
            unit: '',
            icon: Clock3,
            color: 'green',
            sub: '客户端进程在线时间',
          },
        ].map((metric) => (
          <article className="metric" key={metric.label}>
            <div className="metric-top">
              <span>{metric.label}</span>
              <metric.icon size={18} className={metric.color} />
            </div>
            <strong>
              {metric.value}
              <small>{metric.unit}</small>
            </strong>
            <p>{metric.sub}</p>
          </article>
        ))}
      </div>
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>流量趋势</h2>
            <p>最近 5 分钟 · 每 5 秒采样</p>
          </div>
          <div className="legend">
            <span>
              <i className="green-bg" />
              下载
            </span>
            <span>
              <i className="blue-bg" />
              上传
            </span>
            <b>LIVE</b>
          </div>
        </div>
        <TrafficChart stats={stats} />
      </section>
      <div className="overview-grid">
        <section className="panel connection-card">
          <div className="panel-heading">
            <h2>当前连接</h2>
            <Globe2 size={18} />
          </div>
          <div className="server-row">
            <div className="server-icon">
              <Globe2 size={22} />
            </div>
            <div>
              <strong>主服务器</strong>
              <code>{session?.runtime.server_address || '等待客户端信息'}</code>
            </div>
          </div>
          <div className="endpoint-row">
            <span>SOCKS5</span>
            <code>{session?.runtime.socks5 || '—'}</code>
          </div>
          <div className="endpoint-row">
            <span>HTTP 代理</span>
            <code>{session?.runtime.http_proxy || '—'}</code>
          </div>
          <button className="text-link" onClick={() => navigate('connection')}>
            打开连接配置
            <ArrowUpRight size={14} />
          </button>
        </section>
        <section className="panel">
          <div className="panel-heading">
            <h2>DNS 与分流</h2>
            <ShieldCheck size={18} />
          </div>
          <div className="dns-summary">
            <strong>
              {(counters.dns_tunnel || 0) +
                (counters.dns_bypass || 0) +
                (counters.dns_block || 0)}
              <span>次 DNS 查询</span>
            </strong>
            <span>实时累计</span>
          </div>
          <div className="dns-bars">
            {[
              {
                name: '隧道解析',
                value: counters.dns_tunnel || 0,
                color: 'blue-bg',
              },
              {
                name: '直连解析',
                value: counters.dns_bypass || 0,
                color: 'green-bg',
              },
              {
                name: '已拦截',
                value: counters.dns_block || 0,
                color: 'muted-bg',
              },
            ].map((item) => (
              <div key={item.name}>
                <span>
                  <i className={item.color} />
                  {item.name}
                </span>
                <strong>{item.value}</strong>
              </div>
            ))}
          </div>
          <button className="text-link" onClick={() => navigate('dns')}>
            管理 DNS 上游
            <ArrowUpRight size={14} />
          </button>
        </section>
      </div>
      <div className="quick-heading">
        <h2>按你的方式连接</h2>
        <span>所有配置，集中管理</span>
      </div>
      <div className="quick-grid">
        {sections.slice(1, 5).map((section) => {
          const Icon = icons[section.icon]
          return (
            <button
              className="quick-card"
              key={section.id}
              onClick={() => navigate(section.id)}
            >
              <Icon size={22} />
              <strong>{section.title}</strong>
              <span>{section.sub}</span>
              <ChevronRight size={16} />
            </button>
          )
        })}
      </div>
    </>
  )
}

function App() {
  const {
    connected,
    session,
    setSession,
    stats,
    error: connectionError,
    request,
    pause,
    pausedReason,
  } = useControl()
  const [page, setPage] = useState('overview')
  const [draft, setDraft] = useState<Config | null>(null)
  const [base, setBase] = useState<Session | null>(null)
  const [search, setSearch] = useState('')
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState<{
    text: string
    error?: boolean
  } | null>(null)
  const [confirmReload, setConfirmReload] = useState(false)
  const [mobile, setMobile] = useState(false)
  const dirty =
    !!draft &&
    !!base &&
    JSON.stringify(clean(draft)) !== JSON.stringify(clean(base.config))
  useEffect(() => {
    if (
      session &&
      (!base || (!dirty && JSON.stringify(session) !== JSON.stringify(base)))
    ) {
      setBase(session)
      setDraft(structuredClone(session.config))
    }
  }, [session, base, dirty])
  useEffect(() => {
    const listener = (event: BeforeUnloadEvent) => {
      if (dirty) event.preventDefault()
    }
    window.addEventListener('beforeunload', listener)
    return () => window.removeEventListener('beforeunload', listener)
  }, [dirty])
  const activeSection = sections.find((section) => section.id === page)
  const navigate = (next: string) => {
    setPage(next)
    setSearch('')
    setMobile(false)
    setNotice(null)
  }
  async function reload() {
    setBusy(true)
    try {
      const fresh = (await request('config.get')) as Session
      setSession(fresh)
      setBase(fresh)
      setDraft(structuredClone(fresh.config))
      setNotice({ text: '已加载磁盘上的最新配置' })
    } catch (error) {
      setNotice({ text: String((error as Error).message), error: true })
    } finally {
      setBusy(false)
      setConfirmReload(false)
    }
  }
  async function save(validateOnly = false) {
    if (!draft || !base) return
    setBusy(true)
    setNotice(null)
    try {
      const result = await request(
        validateOnly ? 'config.validate' : 'config.save',
        { config: clean(draft), revision: base.revision },
      )
      if (validateOnly) setNotice({ text: '配置校验通过' })
      else {
        const fresh = result as Session
        setBase(fresh)
        setSession(fresh)
        setDraft(structuredClone(fresh.config))
        setNotice({ text: '配置已保存并应用，无需重启客户端。' })
        if (fresh.runtime.dashboard) {
          const destination = dashboardUrl(
            fresh.runtime.dashboard,
            location.href,
          )
          if (destination === null) {
            pause()
            setNotice({ text: '配置已保存并应用，控制面板已关闭。' })
          } else if (fresh.access_allowed === false) {
            pause('denied')
            setNotice({
              text: '配置已应用，新的访问规则不允许当前设备继续访问面板。',
            })
          } else if (destination !== location.origin) {
            pause('moving')
            setNotice({ text: '配置已应用，正在切换到新的控制面板地址…' })
            setTimeout(() => location.assign(destination), 100)
          }
        }
      }
    } catch (error) {
      setNotice({ text: (error as Error).message, error: true })
    } finally {
      setBusy(false)
    }
  }
  const keys = activeSection?.keys || []
  const unknownKeys = draft
    ? Object.keys(draft).filter(
        (key) =>
          !sections.some((section) =>
            (section.keys as readonly string[]).includes(key),
          ),
      )
    : []
  return (
    <div className="app-shell">
      <aside className={mobile ? 'sidebar mobile-open' : 'sidebar'}>
        <a
          className="brand"
          href="#"
          onClick={(e) => {
            e.preventDefault()
            navigate('overview')
          }}
        >
          <span className="brand-mark">r</span>
          <strong>
            rVPN<span>CONTROL</span>
          </strong>
        </a>
        <div className="nav-caption">工作空间</div>
        <nav>
          <button
            className={page === 'overview' ? 'nav-item active' : 'nav-item'}
            onClick={() => navigate('overview')}
          >
            <LayoutDashboard size={19} />
            <span>概览</span>
            <span className="nav-live">LIVE</span>
          </button>
          <div className="nav-caption configuration-label">配置管理</div>
          {sections.map((section) => {
            const Icon = icons[section.icon]
            return (
              <button
                className={page === section.id ? 'nav-item active' : 'nav-item'}
                key={section.id}
                onClick={() => navigate(section.id)}
              >
                <Icon size={19} />
                <span>{section.title}</span>
                {page === section.id && <ChevronRight size={14} />}
              </button>
            )
          })}
          {unknownKeys.length > 0 && (
            <button
              className={page === 'other' ? 'nav-item active' : 'nav-item'}
              onClick={() => navigate('other')}
            >
              <SlidersHorizontal size={19} />
              其他配置
            </button>
          )}
        </nav>
        <div className="sidebar-bottom">
          <div className="local-badge">
            <ShieldCheck size={18} />
            <div>
              本机控制面板<span>所有资源已内嵌</span>
            </div>
          </div>
          <div className="build-label">
            rVPN v{session?.version || '—'}
            <span>DESKTOP CLIENT</span>
          </div>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            <button
              className="icon-button menu-button"
              aria-label="切换导航"
              onClick={() => setMobile(!mobile)}
            >
              <Layers3 size={20} />
            </button>
            <span>控制面板</span>
            <ChevronRight size={13} />
            <strong>
              {activeSection?.title ||
                (page === 'overview' ? '概览' : '其他配置')}
            </strong>
          </div>
          <div className="topbar-actions">
            <span
              className={`connection-indicator ${connected ? 'connected' : ''}`}
            >
              <i />
              {connected
                ? '程序已连接'
                : pausedReason === 'closed'
                  ? '面板已关闭'
                  : pausedReason === 'denied'
                    ? '访问权限已更新'
                    : pausedReason === 'moving'
                      ? '正在切换'
                      : '连接中'}
            </span>
            <span className="local-label">LOCAL</span>
            <button
              className="icon-button"
              aria-label="查看使用帮助"
              onClick={() =>
                setNotice({
                  text: '点击「保存并应用」立即生效。网络设置变更会重新建立连接；相对路径基于配置文件目录。',
                })
              }
            >
              <CircleHelp size={19} />
            </button>
          </div>
        </header>
        <main>
          <div className="page-heading">
            <div>
              <div className="eyebrow">
                RVPN / {page === 'overview' ? 'WORKSPACE' : 'CONFIGURATION'}
              </div>
              <h2>
                {page === 'overview'
                  ? '网络概览'
                  : activeSection?.title || '其他配置'}
              </h2>
              <p>
                {page === 'overview'
                  ? '让连接清晰可见。'
                  : activeSection?.sub || '配置文件中的附加设置'}
              </p>
            </div>
            <span className="sync-label">
              <RefreshCw size={13} />
              {connected
                ? 'WebSocket 实时同步'
                : pausedReason
                  ? '已停止同步'
                  : '正在重新连接'}
            </span>
          </div>
          {(notice || connectionError) && (
            <div
              className={`notice ${notice?.error ? 'error' : ''}`}
              role={notice?.error ? 'alert' : 'status'}
            >
              <span>{notice?.text || connectionError}</span>
              <button
                className="icon-button"
                aria-label="关闭提示"
                onClick={() => setNotice(null)}
              >
                <X size={16} />
              </button>
            </div>
          )}
          {base?.pending_changes && (
            <div className="restart-banner">
              <RefreshCw size={17} />
              <span>
                检测到配置文件的外部修改。检查设置后点击「保存并应用」更新运行配置。
              </span>
            </div>
          )}
          {stats?.runtime_error && (
            <div className="notice error" role="alert">
              <ShieldCheck size={18} />
              <span>
                VPN 已停止：{stats.runtime_error}
                。你仍可修改配置并点击「保存并应用」恢复运行。
              </span>
            </div>
          )}
          {page === 'overview' ? (
            <Overview
              session={session}
              stats={stats}
              connected={connected}
              navigate={navigate}
            />
          ) : !draft ? (
            <div className="loading-state">
              <RefreshCw size={24} className="animate-spin" />
              <h2>正在读取客户端配置</h2>
              <p>连接建立后，配置会自动显示。</p>
            </div>
          ) : (
            <>
              <div className="config-toolbar">
                <div className="search-field">
                  <Search size={17} />
                  <input
                    aria-label="搜索配置项"
                    placeholder="搜索配置名称或字段…"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                  />
                  <kbd>配置</kbd>
                </div>
                <button
                  className="button tertiary"
                  disabled={!connected || busy}
                  onClick={() =>
                    dirty ? setConfirmReload(true) : void reload()
                  }
                >
                  <RefreshCw size={15} />
                  重新加载
                </button>
              </div>
              <div className="config-sections">
                {(page === 'other' ? unknownKeys : keys)
                  .filter((key) => key in draft)
                  .map((key) => {
                    const value = draft[key]
                    const filter = (name: string) =>
                      !search ||
                      `${name} ${labels[name] || ''}`
                        .toLowerCase()
                        .includes(search.toLowerCase())
                    const object =
                      !!value &&
                      typeof value === 'object' &&
                      !Array.isArray(value) &&
                      key !== 'routing'
                    const entries = object
                      ? Object.entries(value).filter(
                          ([name]) => filter(key) || filter(name),
                        )
                      : []
                    if (search && !filter(key) && !entries.length) return null
                    return (
                      <section className="panel config-panel" key={key}>
                        <div className="panel-heading">
                          <div>
                            <h2>{labels[key] || key}</h2>
                            <p>{hints[key] || key}</p>
                          </div>
                          <SlidersHorizontal size={18} />
                        </div>
                        <div className="fields">
                          {key === 'server' ? (
                            <ServerEditor
                              value={value as unknown[]}
                              onChange={(next) =>
                                setDraft(setPath(draft, [key], next))
                              }
                            />
                          ) : key === 'routing' ? (
                            <RoutingEditor
                              value={value as Config}
                              onChange={(next) =>
                                setDraft(setPath(draft, [key], next))
                              }
                            />
                          ) : object ? (
                            entries.map(([name, v]) => (
                              <Field
                                key={name}
                                name={name}
                                value={v}
                                onChange={(next) =>
                                  setDraft(setPath(draft, [key, name], next))
                                }
                              />
                            ))
                          ) : (
                            <Field
                              name={key}
                              value={value}
                              onChange={(next) =>
                                setDraft(setPath(draft, [key], next))
                              }
                            />
                          )}
                        </div>
                      </section>
                    )
                  })}
              </div>
              <div className="save-bar">
                <div>
                  <span className={`dot ${dirty ? 'edited' : 'live'}`} />
                  <strong>{dirty ? '有未保存的修改' : '配置已同步'}</strong>
                  <span className="save-caption">
                    网络设置变更会重新建立连接
                  </span>
                </div>
                <div>
                  <button
                    className="button tertiary"
                    disabled={!connected || busy}
                    onClick={() => void save(true)}
                  >
                    <Check size={15} />
                    校验配置
                  </button>
                  <button
                    className="button primary"
                    disabled={
                      !connected ||
                      busy ||
                      (!dirty &&
                        !base?.pending_changes &&
                        !stats?.runtime_error)
                    }
                    onClick={() => void save()}
                  >
                    {busy ? (
                      <RefreshCw size={16} className="animate-spin" />
                    ) : (
                      <Save size={16} />
                    )}
                    {busy ? '正在应用…' : '保存并应用'}
                  </button>
                </div>
              </div>
            </>
          )}
          <footer>
            <span>
              <ShieldCheck size={13} />
              rVPN · 连接自由，始终私密
            </span>
            <span title={base?.path}>{base?.path || '等待配置路径'}</span>
          </footer>
        </main>
      </div>
      {confirmReload && (
        <div className="modal-backdrop">
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="reload-title"
            className="modal"
          >
            <h2 id="reload-title">放弃未保存的修改？</h2>
            <p>重新加载将使用磁盘上的最新配置，当前页面中的修改会被替换。</p>
            <div>
              <button
                className="button tertiary"
                onClick={() => setConfirmReload(false)}
              >
                继续编辑
              </button>
              <button className="button primary" onClick={() => void reload()}>
                重新加载
              </button>
            </div>
          </section>
        </div>
      )}
    </div>
  )
}

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
