import { useCallback, useEffect, useRef, useState } from 'react'
import type { Session, Stats } from './model'

type Pending = {
  method: string
  resolve: (value: unknown) => void
  reject: (error: Error) => void
  timer: ReturnType<typeof setTimeout>
}
export function useControl() {
  const [connected, setConnected] = useState(false)
  const [session, setSession] = useState<Session | null>(null)
  const [stats, setStats] = useState<Stats | null>(null)
  const [error, setError] = useState('')
  const [pausedReason, setPausedReason] = useState('')
  const socket = useRef<WebSocket | null>(null)
  const pending = useRef(new Map<number, Pending>())
  const sequence = useRef(0)
  const paused = useRef(false)
  useEffect(() => {
    let disposed = false
    let retry: ReturnType<typeof setTimeout>
    let attempt = 0
    const failPending = () => {
      for (const item of pending.current.values()) {
        clearTimeout(item.timer)
        item.reject(new Error('连接已断开，保存结果请重新加载确认'))
      }
      pending.current.clear()
    }
    function connect() {
      if (paused.current) return
      const ws = new WebSocket(
        `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/ws`,
      )
      socket.current = ws
      ws.onopen = () => {
        if (disposed || socket.current !== ws) return
        attempt = 0
        setConnected(true)
        setError('')
      }
      ws.onmessage = (event) => {
        if (disposed || socket.current !== ws) return
        try {
          const message = JSON.parse(event.data)
          if (message.type === 'session' || message.type === 'configuration')
            setSession(message.data)
          if (message.type === 'stats') setStats(message.data)
          if (message.type === 'response') {
            const item = pending.current.get(message.id)
            if (item) {
              clearTimeout(item.timer)
              pending.current.delete(message.id)
              if (message.ok) {
                if (item.method === 'config.save' && message.data?.runtime)
                  setStats((previous) =>
                    previous ? { ...previous, runtime_error: null } : previous,
                  )
                item.resolve(message.data)
              } else item.reject(new Error(message.error))
            }
          }
        } catch {
          setError('收到无法识别的程序消息')
        }
      }
      ws.onclose = () => {
        if (disposed || socket.current !== ws || paused.current) return
        setConnected(false)
        failPending()
        retry = setTimeout(connect, Math.min(1000 * 2 ** attempt++, 10000))
      }
      ws.onerror = () => {
        if (!disposed && socket.current === ws)
          setError('暂时无法连接客户端，正在重试…')
      }
    }
    connect()
    return () => {
      disposed = true
      clearTimeout(retry)
      socket.current?.close()
      failPending()
    }
  }, [])
  const request = useCallback(
    (method: string, payload: Record<string, unknown> = {}) =>
      new Promise<unknown>((resolve, reject) => {
        if (socket.current?.readyState !== WebSocket.OPEN) {
          reject(new Error('程序连接已断开'))
          return
        }
        const id = ++sequence.current
        const timer = setTimeout(() => {
          pending.current.delete(id)
          reject(new Error('操作超时，请重新加载确认配置'))
        }, 60000)
        pending.current.set(id, { method, resolve, reject, timer })
        socket.current.send(JSON.stringify({ id, method, ...payload }))
      }),
    [],
  )
  const pause = useCallback((reason = 'closed') => {
    paused.current = true
    setPausedReason(reason)
    socket.current?.close()
    setConnected(false)
    setError('')
  }, [])
  return {
    connected,
    session,
    setSession,
    stats,
    error,
    request,
    pause,
    pausedReason,
  }
}
