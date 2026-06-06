import { spawn as nodeSpawn, type ChildProcess } from 'child_process'
import { createHash } from 'crypto'
import { chmod, mkdir, readFile, rename, unlink, writeFile } from 'fs/promises'
import { existsSync } from 'fs'
import { homedir } from 'os'
import { dirname, join } from 'path'
import { createServer } from 'net'

export type ThreadSessionStatus = 'activating' | 'active' | 'archived' | 'dead'

export interface ThreadSession {
  session_id: string
  port: number
  pid: number
  status: ThreadSessionStatus
  created_at: string
  last_active_at: string
  cwd: string
  slack_context_sent_at?: string
}

export type ThreadSessionRegistry = Record<string, ThreadSession>

export interface SpawnedProcess {
  pid?: number
  unref?: () => void
}

export type SpawnAgent = (
  command: string,
  args: string[],
  options: { cwd: string; detached: true; stdio: 'ignore' },
) => SpawnedProcess

export interface ThreadRouterOptions {
  stateDir?: string
  agentapiPath?: string
  basePort?: number
  maxPorts?: number
  cwd?: string
  now?: () => number
  fetch?: (input: string, init?: RequestInit) => Promise<Response>
  spawnAgent?: SpawnAgent
  portIsAvailable?: (port: number) => Promise<boolean>
  killProcess?: (pid: number) => void | Promise<void>
  lockTimeoutMs?: number
  lockPollMs?: number
  activationTimeoutMs?: number
  statusPollMs?: number
  forwardTimeoutMs?: number
  includeSlackContext?: boolean
}

interface AgentStatusBody {
  status?: unknown
}

interface AgentMessage {
  id: number
  role: 'agent' | 'user'
  content: string
  time: string
}

interface MessagesBody {
  messages?: AgentMessage[]
}

const DEFAULT_BASE_PORT = 3010
const DEFAULT_MAX_PORTS = 90
const DEFAULT_LOCK_TIMEOUT_MS = 10_000
const DEFAULT_LOCK_POLL_MS = 50
const DEFAULT_ACTIVATION_TIMEOUT_MS = 30_000
const DEFAULT_STATUS_POLL_MS = 1_000
const DEFAULT_FORWARD_TIMEOUT_MS = 15 * 60 * 1000
const SAFE_SESSION_KEY_RE = /^[A-Za-z0-9:._-]+$/
const ANSI_ESCAPE_RE = /\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1B\\))/g
const CONTROL_CHAR_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g
const TUI_PREFIX_RE = /^[ \t]*[●⏺]\s*/
const TUI_TIMED_STATUS_RE =
  /^[✻✶✱✢]\s+.*\bfor\s+\d+(?:\.\d+)?\s*(?:ms|s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours)\b/i
const TUI_TOOL_STATUS_RE = /^(?:Ran|Searched|Called)\b(?:\s|:|$)/
const SLACK_INBOUND_ECHO_RE = /^←\s*slack\s*·\s*/i
const SLACK_ECHO_CONTINUATION_RE = /^.{1,32}…$/
const CONTEXT_USAGE_RE = /^(\d+%)\s+context used$/i
const MARKDOWN_LINE_PREFIX_RE = /^([ \t]{0,3}(?:(?:[-*+]|\d+[.)])[ \t]+|>[ \t]?))/
const EXCESS_HORIZONTAL_SPACE_RE = /[ \t]{2,}/g

const inFlight = new Map<string, Promise<ThreadSession>>()

export function defaultStateDir(): string {
  return process.env['SLACK_STATE_DIR'] || join(homedir(), '.claude', 'channels', 'slack')
}

export function registryFilePath(stateDir = defaultStateDir()): string {
  return join(stateDir, 'thread_sessions.json')
}

export function registryLockPath(stateDir = defaultStateDir()): string {
  return `${registryFilePath(stateDir)}.lock`
}

export function buildSessionKey(channel: string, threadTs: string): string {
  if (!channel) throw new Error('buildSessionKey: channel is required')
  if (!threadTs) throw new Error('buildSessionKey: thread timestamp is required')
  return `${channel}:${threadTs}`
}

export function sessionKeyFromMeta(meta: Record<string, string>): string {
  const channel = meta['chat_id']
  const threadTs = meta['thread_ts'] || meta['ts']
  if (!channel) throw new Error('sessionKeyFromMeta: meta.chat_id is required')
  if (!threadTs) throw new Error('sessionKeyFromMeta: meta.thread_ts or meta.ts is required')
  return buildSessionKey(channel, threadTs)
}

export function stateFilePathForKey(stateDir: string, key: string): string {
  if (!SAFE_SESSION_KEY_RE.test(key)) {
    throw new Error(`stateFilePathForKey: invalid session key: ${JSON.stringify(key)}`)
  }
  return join(stateDir, 'sessions', `${key}.state`)
}

export function claudeSessionIdForKey(key: string): string {
  const hex = createHash('sha256').update(`slack-thread:${key}`).digest('hex')
  const variant = ((parseInt(hex[16]!, 16) & 0x3) | 0x8).toString(16)
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    `5${hex.slice(13, 16)}`,
    `${variant}${hex.slice(17, 20)}`,
    hex.slice(20, 32),
  ].join('-')
}

export function buildAgentapiCommand(
  port: number,
  key: string,
  stateDir = defaultStateDir(),
  agentapiPath = join(homedir(), 'bin', 'agentapi'),
): { command: string; args: string[]; stateFile: string; claudeSessionId: string } {
  const stateFile = stateFilePathForKey(stateDir, key)
  const claudeSessionId = claudeSessionIdForKey(key)

  // agentapi v0.12.2 rejects server-level --session-id. Claude accepts only
  // UUID session IDs, so the thread key is carried by the state file/name and
  // a deterministic UUID is used for Claude's session identity.
  return {
    command: agentapiPath,
    args: [
      'server',
      'claude',
      '-p',
      String(port),
      '--state-file',
      stateFile,
      '--',
      '--session-id',
      claudeSessionId,
      '--name',
      key,
      '--model',
      'claude-opus-4-6[1m]',
      '--allowedTools',
      'Read Edit Write Bash',
    ],
    stateFile,
    claudeSessionId,
  }
}

export async function readRegistryFile(path: string): Promise<ThreadSessionRegistry> {
  if (!existsSync(path)) return {}
  const raw = await readFile(path, 'utf8')
  if (!raw.trim()) return {}
  const parsed = JSON.parse(raw) as unknown
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('thread session registry must be a JSON object')
  }
  return parsed as ThreadSessionRegistry
}

export async function writeRegistryAtomic(
  path: string,
  registry: ThreadSessionRegistry,
): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 })
  const tmp = `${path}.tmp.${process.pid}`
  const json = JSON.stringify(registry, null, 2)

  try {
    await writeFile(tmp, json, { mode: 0o600, flag: 'wx' })
    await chmod(tmp, 0o600)
    await rename(tmp, path)
  } catch (err) {
    try {
      await unlink(tmp)
    } catch {
      /* no-op */
    }
    throw err
  }
}

export async function readRegistry(stateDir = defaultStateDir()): Promise<ThreadSessionRegistry> {
  return withRegistryLock(stateDir, async () => readRegistryFile(registryFilePath(stateDir)))
}

export async function writeRegistry(
  stateDir: string,
  registry: ThreadSessionRegistry,
): Promise<void> {
  await withRegistryLock(stateDir, async () => {
    await writeRegistryAtomic(registryFilePath(stateDir), registry)
  })
}

export async function ensureSession(
  channel: string,
  threadTs: string,
  options: ThreadRouterOptions = {},
): Promise<ThreadSession> {
  const stateDir = options.stateDir || defaultStateDir()
  const key = buildSessionKey(channel, threadTs)
  const flightKey = `${stateDir}\0${key}`
  const existing = inFlight.get(flightKey)
  if (existing) return existing

  const promise = ensureSessionUnshared(key, options, stateDir)
  inFlight.set(flightKey, promise)
  try {
    return await promise
  } finally {
    inFlight.delete(flightKey)
  }
}

export async function forwardMessage(
  port: number,
  text: string,
  options: ThreadRouterOptions = {},
  meta?: Record<string, string>,
): Promise<string> {
  const fetchImpl = options.fetch || fetch
  const baseUrl = `http://127.0.0.1:${port}`
  const content = meta
    ? formatForwardedMessage(text, meta, {
      includeSlackContext: options.includeSlackContext ?? true,
    })
    : text

  await fetchJson<{ ok?: boolean }>(fetchImpl, `${baseUrl}/message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content, type: 'user' }),
  })

  await waitForStable(port, options)

  const body = await fetchJson<MessagesBody>(fetchImpl, `${baseUrl}/messages`)
  const agentMessages = (body.messages || []).filter(
    (message) => message.role === 'agent' && typeof message.content === 'string',
  )
  return sanitizeAgentReply(agentMessages.at(-1)?.content || '')
}

export function sanitizeAgentReply(content: string): string {
  const sanitizedLines: string[] = []
  let inFence = false
  let fenceMarker = ''
  let skippingSlackEchoContinuation = false

  for (const rawLine of content.replace(/\r\n?/g, '\n').split('\n')) {
    const line = rawLine.replace(ANSI_ESCAPE_RE, '').replace(CONTROL_CHAR_RE, '').trimEnd()
    const trimmedStart = line.trimStart()
    const fence = trimmedStart.match(/^(```+|~~~+)/)?.[1]

    if (inFence) {
      sanitizedLines.push(line)
      if (fence && fence[0] === fenceMarker[0] && fence.length >= fenceMarker.length) {
        inFence = false
        fenceMarker = ''
      }
      continue
    }

    if (fence) {
      sanitizedLines.push(line)
      inFence = true
      fenceMarker = fence
      continue
    }

    const withoutTuiPrefix = line.replace(TUI_PREFIX_RE, '')
    const trimmed = withoutTuiPrefix.trim()
    if (skippingSlackEchoContinuation) {
      if (!trimmed) {
        skippingSlackEchoContinuation = false
        sanitizedLines.push('')
        continue
      }

      if (SLACK_ECHO_CONTINUATION_RE.test(trimmed)) {
        continue
      }

      skippingSlackEchoContinuation = false
    }

    if (
      trimmed &&
      (TUI_TIMED_STATUS_RE.test(trimmed) ||
        TUI_TOOL_STATUS_RE.test(trimmed))
    ) {
      continue
    }

    if (trimmed && SLACK_INBOUND_ECHO_RE.test(trimmed)) {
      skippingSlackEchoContinuation = true
      continue
    }

    const contextUsage = trimmed.match(CONTEXT_USAGE_RE)
    if (contextUsage) {
      sanitizedLines.push(`${contextUsage[1]} context used`)
      continue
    }

    sanitizedLines.push(normalizeReplyLine(withoutTuiPrefix))
  }

  return sanitizedLines.join('\n').replace(/\n{3,}/g, '\n\n').trim()
}

function normalizeReplyLine(line: string): string {
  if (!line.trim()) return ''

  const markdownPrefix = line.match(MARKDOWN_LINE_PREFIX_RE)?.[1]
  if (markdownPrefix) {
    return markdownPrefix + line.slice(markdownPrefix.length).replace(EXCESS_HORIZONTAL_SPACE_RE, ' ')
  }

  if (/^(?: {4,}|\t)/.test(line)) {
    return line
  }

  return line.trimStart().replace(EXCESS_HORIZONTAL_SPACE_RE, ' ')
}

function escapeAttr(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
}

export function formatForwardedMessage(
  text: string,
  meta: Record<string, string>,
  options: { includeSlackContext?: boolean } = {},
): string {
  const attrs = Object.entries(meta)
    .filter(([, value]) => value !== '')
    .map(([key, value]) => `${key}="${escapeAttr(value)}"`)
    .join(' ')
  const channel = `<channel source="slack" ${attrs}>\n${text}\n</channel>`
  if (options.includeSlackContext === false) return channel
  return `${buildSlackContextPrompt(meta)}\n\n${channel}`
}

export function buildSlackContextPrompt(meta: Record<string, string>): string {
  const attrs: Record<string, string> = {
    channel_id: meta['chat_id'] || '',
    thread_ts: meta['thread_ts'] || meta['ts'] || '',
    ts: meta['ts'] || '',
    user: meta['user'] || '',
    user_id: meta['user_id'] || '',
    message_id: meta['message_id'] || meta['ts'] || '',
    attachment_count: meta['attachment_count'] || '0',
  }
  if (meta['attachment_paths']) {
    attrs.attachment_paths = meta['attachment_paths']
  }

  const renderedAttrs = Object.entries(attrs)
    .map(([key, value]) => `${key}="${escapeAttr(value)}"`)
    .join(' ')

  return [
    `<slack_context ${renderedAttrs}>`,
    'You are replying in this Slack thread. Answer concisely for Slack.',
    'If attachment_paths is present, inspect those local files with Read/Bash as needed before answering.',
    'If context, history, search results, or attachments are missing, say what to fetch instead of assuming.',
    '</slack_context>',
  ].join('\n')
}

export async function claimSlackContextForSession(
  channel: string,
  threadTs: string,
  options: ThreadRouterOptions = {},
): Promise<boolean> {
  const stateDir = options.stateDir || defaultStateDir()
  const key = buildSessionKey(channel, threadTs)

  return withRegistryLock(stateDir, async () => {
    const registry = await readRegistryFile(registryFilePath(stateDir))
    const session = registry[key]
    if (!session) return true
    if (session.slack_context_sent_at) return false

    registry[key] = {
      ...session,
      slack_context_sent_at: new Date((options.now || Date.now)()).toISOString(),
    }
    await writeRegistryAtomic(registryFilePath(stateDir), registry)
    return true
  })
}

export async function cleanupIdle(
  ttlMs: number,
  options: ThreadRouterOptions = {},
): Promise<string[]> {
  const stateDir = options.stateDir || defaultStateDir()
  const now = options.now || Date.now
  const killProcess = options.killProcess || defaultKillProcess

  return withRegistryLock(stateDir, async () => {
    const registry = await readRegistryFile(registryFilePath(stateDir))
    const staleKeys: string[] = []
    const cutoff = now() - ttlMs

    for (const [key, session] of Object.entries(registry)) {
      if (session.status !== 'active' && session.status !== 'activating') continue
      const lastActive = Date.parse(session.last_active_at)
      if (!Number.isFinite(lastActive) || lastActive > cutoff) continue

      if (session.pid > 0) {
        await killProcess(session.pid)
      }
      registry[key] = {
        ...session,
        pid: 0,
        status: 'archived',
        last_active_at: new Date(now()).toISOString(),
      }
      staleKeys.push(key)
    }

    if (staleKeys.length) {
      await writeRegistryAtomic(registryFilePath(stateDir), registry)
    }
    return staleKeys
  })
}

async function ensureSessionUnshared(
  key: string,
  options: ThreadRouterOptions,
  stateDir: string,
): Promise<ThreadSession> {
  const existing = await readRegistry(stateDir).then((registry) => registry[key])
  if (existing?.status === 'active') {
    if (await isAgentHealthy(existing.port, options)) {
      return touchSession(key, existing, options, stateDir)
    }
    await markDeadIfCurrent(key, existing, options, stateDir)
  }
  if (existing?.status === 'activating') {
    return waitForActivation(key, options, stateDir)
  }

  return activateSession(key, options, stateDir)
}

async function activateSession(
  key: string,
  options: ThreadRouterOptions,
  stateDir: string,
): Promise<ThreadSession> {
  const claim = await claimActivation(key, options, stateDir)
  if (claim.status === 'active') {
    return touchSession(key, claim, options, stateDir)
  }
  if (claim.status !== 'activating') {
    return waitForActivation(key, options, stateDir)
  }

  const cwd = options.cwd || process.cwd()
  const agentapiPath = options.agentapiPath || join(homedir(), 'bin', 'agentapi')
  const { command, args } = buildAgentapiCommand(claim.port, key, stateDir, agentapiPath)
  const spawnAgent = options.spawnAgent || defaultSpawnAgent

  try {
    await mkdir(join(stateDir, 'sessions'), { recursive: true, mode: 0o700 })
    const child = spawnAgent(command, args, { cwd, detached: true, stdio: 'ignore' })
    child.unref?.()
    const pid = child.pid || 0
    await waitForAgentHealthy(claim.port, options)
    return markActive(key, claim, pid, options, stateDir)
  } catch (err) {
    await markDeadIfCurrent(key, claim, options, stateDir)
    throw err
  }
}

async function claimActivation(
  key: string,
  options: ThreadRouterOptions,
  stateDir: string,
): Promise<ThreadSession> {
  return withRegistryLock(stateDir, async () => {
    const registry = await readRegistryFile(registryFilePath(stateDir))
    const current = registry[key]
    if (current?.status === 'active' || current?.status === 'activating') {
      return current
    }

    const nowIso = new Date((options.now || Date.now)()).toISOString()
    const port = await nextFreePort(registry, options)
    const session: ThreadSession = {
      session_id: claudeSessionIdForKey(key),
      port,
      pid: 0,
      status: 'activating',
      created_at: current?.created_at || nowIso,
      last_active_at: nowIso,
      cwd: options.cwd || process.cwd(),
    }
    registry[key] = session
    await writeRegistryAtomic(registryFilePath(stateDir), registry)
    return session
  })
}

async function touchSession(
  key: string,
  session: ThreadSession,
  options: ThreadRouterOptions,
  stateDir: string,
): Promise<ThreadSession> {
  return withRegistryLock(stateDir, async () => {
    const registry = await readRegistryFile(registryFilePath(stateDir))
    const current = registry[key]
    if (!current || current.port !== session.port) return session
    const touched: ThreadSession = {
      ...current,
      last_active_at: new Date((options.now || Date.now)()).toISOString(),
    }
    registry[key] = touched
    await writeRegistryAtomic(registryFilePath(stateDir), registry)
    return touched
  })
}

async function markActive(
  key: string,
  session: ThreadSession,
  pid: number,
  options: ThreadRouterOptions,
  stateDir: string,
): Promise<ThreadSession> {
  return withRegistryLock(stateDir, async () => {
    const registry = await readRegistryFile(registryFilePath(stateDir))
    const current = registry[key]
    if (!current || current.port !== session.port || current.status !== 'activating') {
      return current || session
    }
    const active: ThreadSession = {
      ...current,
      pid,
      status: 'active',
      last_active_at: new Date((options.now || Date.now)()).toISOString(),
    }
    registry[key] = active
    await writeRegistryAtomic(registryFilePath(stateDir), registry)
    return active
  })
}

async function markDeadIfCurrent(
  key: string,
  session: ThreadSession,
  options: ThreadRouterOptions,
  stateDir: string,
): Promise<void> {
  await withRegistryLock(stateDir, async () => {
    const registry = await readRegistryFile(registryFilePath(stateDir))
    const current = registry[key]
    if (!current || current.port !== session.port) return
    registry[key] = {
      ...current,
      pid: 0,
      status: 'dead',
      last_active_at: new Date((options.now || Date.now)()).toISOString(),
    }
    await writeRegistryAtomic(registryFilePath(stateDir), registry)
  })
}

async function waitForActivation(
  key: string,
  options: ThreadRouterOptions,
  stateDir: string,
): Promise<ThreadSession> {
  const deadline = Date.now() + (options.activationTimeoutMs || DEFAULT_ACTIVATION_TIMEOUT_MS)
  const pollMs = options.statusPollMs || DEFAULT_STATUS_POLL_MS

  while (Date.now() <= deadline) {
    const session = await readRegistry(stateDir).then((registry) => registry[key])
    if (!session || session.status === 'dead' || session.status === 'archived') {
      return activateSession(key, options, stateDir)
    }
    if (session.status === 'active' && await isAgentHealthy(session.port, options)) {
      return touchSession(key, session, options, stateDir)
    }
    await sleep(pollMs)
  }

  throw new Error(`Timed out waiting for thread session activation: ${key}`)
}

async function waitForAgentHealthy(
  port: number,
  options: ThreadRouterOptions,
): Promise<void> {
  const deadline = Date.now() + (options.activationTimeoutMs || DEFAULT_ACTIVATION_TIMEOUT_MS)
  const pollMs = options.statusPollMs || DEFAULT_STATUS_POLL_MS

  while (Date.now() <= deadline) {
    if (await isAgentHealthy(port, options)) return
    await sleep(pollMs)
  }

  throw new Error(`Timed out waiting for agentapi on port ${port}`)
}

async function waitForStable(
  port: number,
  options: ThreadRouterOptions,
): Promise<void> {
  const deadline = Date.now() + (options.forwardTimeoutMs || DEFAULT_FORWARD_TIMEOUT_MS)
  const pollMs = options.statusPollMs || DEFAULT_STATUS_POLL_MS

  while (Date.now() <= deadline) {
    const status = await getAgentStatus(port, options)
    if (status === 'stable') return
    await sleep(pollMs)
  }

  throw new Error(`Timed out waiting for agentapi to become stable on port ${port}`)
}

export async function getAgentStatus(
  port: number,
  options: ThreadRouterOptions = {},
): Promise<'running' | 'stable'> {
  const fetchImpl = options.fetch || fetch
  const body = await fetchJson<AgentStatusBody>(fetchImpl, `http://127.0.0.1:${port}/status`)
  if (body.status !== 'running' && body.status !== 'stable') {
    throw new Error(`Unexpected agentapi status: ${String(body.status)}`)
  }
  return body.status
}

async function isAgentHealthy(
  port: number,
  options: ThreadRouterOptions,
): Promise<boolean> {
  try {
    await getAgentStatus(port, options)
    return true
  } catch {
    return false
  }
}

async function nextFreePort(
  registry: ThreadSessionRegistry,
  options: ThreadRouterOptions,
): Promise<number> {
  const basePort = options.basePort || DEFAULT_BASE_PORT
  const maxPorts = options.maxPorts || DEFAULT_MAX_PORTS
  const used = new Set(
    Object.values(registry)
      .filter((session) => session.status === 'active' || session.status === 'activating')
      .map((session) => session.port),
  )
  const portIsAvailable = options.portIsAvailable || defaultPortIsAvailable

  for (let offset = 0; offset < maxPorts; offset++) {
    const port = basePort + offset
    if (used.has(port)) continue
    if (await portIsAvailable(port)) return port
  }

  throw new Error(`No free agentapi ports in range ${basePort}-${basePort + maxPorts - 1}`)
}

async function withRegistryLock<T>(
  stateDir: string,
  fn: () => Promise<T>,
): Promise<T> {
  await mkdir(stateDir, { recursive: true, mode: 0o700 })
  const lockPath = registryLockPath(stateDir)
  await acquireLock(lockPath, stateDir)
  try {
    return await fn()
  } finally {
    try {
      await unlink(lockPath)
    } catch {
      /* no-op */
    }
  }
}

async function acquireLock(lockPath: string, stateDir: string): Promise<void> {
  const deadline = Date.now() + DEFAULT_LOCK_TIMEOUT_MS
  const pollMs = DEFAULT_LOCK_POLL_MS

  while (Date.now() <= deadline) {
    try {
      await writeFile(lockPath, `${process.pid}\n`, { mode: 0o600, flag: 'wx' })
      await chmod(lockPath, 0o600)
      return
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err
      if (await isStaleLock(lockPath)) {
        try {
          await unlink(lockPath)
          continue
        } catch {
          /* another process may have won the cleanup race */
        }
      }
      await sleep(pollMs)
    }
  }

  throw new Error(`Timed out acquiring thread session registry lock in ${stateDir}`)
}

async function isStaleLock(lockPath: string): Promise<boolean> {
  try {
    const raw = await readFile(lockPath, 'utf8')
    const pid = Number.parseInt(raw.trim(), 10)
    if (!pid || pid === process.pid) return true
    process.kill(pid, 0)
    return false
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code
    if (code === 'ESRCH' || code === 'ENOENT') return true
    if (code === 'EPERM') return false
    return true
  }
}

async function fetchJson<T>(
  fetchImpl: (input: string, init?: RequestInit) => Promise<Response>,
  url: string,
  init?: RequestInit,
): Promise<T> {
  const response = await fetchImpl(url, init)
  if (!response.ok) {
    throw new Error(`agentapi request failed: ${response.status} ${response.statusText}`)
  }
  return await response.json() as T
}

function defaultSpawnAgent(
  command: string,
  args: string[],
  options: { cwd: string; detached: true; stdio: 'ignore' },
): ChildProcess {
  return nodeSpawn(command, args, options)
}

function defaultKillProcess(pid: number): void {
  try {
    process.kill(pid, 'TERM')
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ESRCH') throw err
  }
}

function defaultPortIsAvailable(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const server = createServer()
    server.once('error', () => resolve(false))
    server.once('listening', () => {
      server.close(() => resolve(true))
    })
    server.listen(port, '127.0.0.1')
  })
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}
