import { useCallback, useEffect, useRef, useState } from 'react'
import { api, getToken } from './api'

export function useApi<T = any>(path: string | null, deps: any[] = [], pollMs = 0) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const alive = useRef(true)

  const load = useCallback(async () => {
    if (!path) return
    try {
      const res = await api<T>(path)
      if (alive.current) { setData(res); setError(null) }
    } catch (e: any) {
      if (alive.current) setError(e.message || 'Request failed')
    } finally {
      if (alive.current) setLoading(false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path])

  useEffect(() => {
    alive.current = true
    setLoading(true)
    load()
    let t: any
    if (pollMs > 0) t = setInterval(load, pollMs)
    return () => { alive.current = false; if (t) clearInterval(t) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, pollMs, ...deps])

  return { data, error, loading, reload: load }
}

export type LiveTick = {
  type: string; utc: string; tick: number; open_alerts: number; critical: number
  incidents: number; samples: number; health: { host: string; state: string; score: number }[]
  cpu: { t: string; v: number }[]; latency: { t: string; v: number }[]; scenarios: string[]
}

export function useLive() {
  const [tick, setTick] = useState<LiveTick | null>(null)
  const [connected, setConnected] = useState(false)
  const ref = useRef<WebSocket | null>(null)

  useEffect(() => {
    const token = getToken()
    if (!token) return
    let closed = false
    let retry: any
    const connect = () => {
      const proto = location.protocol === 'https:' ? 'wss' : 'ws'
      const ws = new WebSocket(`${proto}://${location.host}/ws?token=${encodeURIComponent(token)}`)
      ref.current = ws
      ws.onopen = () => setConnected(true)
      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data)
          if (msg.type === 'tick') setTick(msg)
        } catch { /* ignore malformed frame */ }
      }
      ws.onclose = () => {
        setConnected(false)
        if (!closed) retry = setTimeout(connect, 4000)
      }
      ws.onerror = () => ws.close()
    }
    connect()
    return () => { closed = true; clearTimeout(retry); ref.current?.close() }
  }, [])

  return { tick, connected }
}

export function useMounted(delay = 60) {
  const [on, setOn] = useState(false)
  useEffect(() => { const t = setTimeout(() => setOn(true), delay); return () => clearTimeout(t) }, [delay])
  return on
}
