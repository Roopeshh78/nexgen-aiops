const TOKEN_KEY = 'nexgen.token'
const USER_KEY = 'nexgen.user'
const API_BASE = 'https://nexgen-aiops.onrender.com'

export type SessionUser = {
  id: string; email: string; name: string; role: string; tenant_id: string; tenant_name?: string
}

export const getToken = () => localStorage.getItem(TOKEN_KEY) || ''
export const getUser = (): SessionUser | null => {
  try { return JSON.parse(localStorage.getItem(USER_KEY) || 'null') } catch { return null }
}
export const setSession = (token: string, user: SessionUser) => {
  localStorage.setItem(TOKEN_KEY, token)
  localStorage.setItem(USER_KEY, JSON.stringify(user))
}
export const clearSession = () => {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(USER_KEY)
}

export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) { super(message); this.status = status }
}

export async function api<T = any>(path: string, opts: RequestInit = {}): Promise<T> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(opts.headers as Record<string, string> || {}),
  }
 const res = await fetch(`${API_BASE}${path}`, { ...opts, headers })
 
  if (res.status === 401) {
    clearSession()
    if (!location.pathname.startsWith('/login')) location.href = '/login'
    throw new ApiError('Session expired', 401)
  }
  const text = await res.text()
  let body: any = null
  try { body = text ? JSON.parse(text) : null } catch { body = text }
  if (!res.ok) {
    const msg = (body && (body.detail || body.message)) || `Request failed (${res.status})`
    throw new ApiError(typeof msg === 'string' ? msg : JSON.stringify(msg), res.status)
  }
  return body as T
}

export const post = <T = any>(path: string, body?: any) =>
  api<T>(path, { method: 'POST', body: JSON.stringify(body ?? {}) })
export const patch = <T = any>(path: string, body?: any) =>
  api<T>(path, { method: 'PATCH', body: JSON.stringify(body ?? {}) })

export const fmtNum = (n: number | null | undefined, digits = 0) =>
  n === null || n === undefined || Number.isNaN(n)
    ? '—'
    : Number(n).toLocaleString('en-US', { maximumFractionDigits: digits, minimumFractionDigits: digits })

export const fmtBytes = (b: number) => (b > 1048576 ? `${(b / 1048576).toFixed(2)} MB` : `${(b / 1024).toFixed(1)} KB`)

export const timeAgo = (iso?: string | null) => {
  if (!iso) return '—'
  const d = new Date(iso).getTime()
  const s = Math.max(0, Math.round((Date.now() - d) / 1000))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

export const clock = (iso?: string | null) => {
  if (!iso) return '—'
  const d = new Date(iso)
  return `${d.toISOString().slice(11, 19)}Z`
}
