import { spawn as nodeSpawn, type ChildProcess } from 'child_process'
import { createHash } from 'crypto'
import { chmod, mkdir, readFile, rename, unlink, writeFile } from 'fs/promises'
import { existsSync } from 'fs'
import { homedir } from 'os'
import { dirname, join, resolve } from 'path'
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
  options: { cwd: string; detached: true; stdio: 'ignore'; env: NodeJS.ProcessEnv },
) => SpawnedProcess

export interface BuildAgentapiCommandOptions {
  cwd?: string
  claudeProjectsDir?: string
  sessionJsonlExists?: (path: string) => boolean
}

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
  pidIsAlive?: (pid: number) => boolean
  killProcess?: (pid: number) => void | Promise<void>
  lockTimeoutMs?: number
  lockPollMs?: number
  activationTimeoutMs?: number
  statusPollMs?: number
  forwardTimeoutMs?: number
  messageSettleMs?: number
  messagePostRetryMs?: number
  replyRepollMs?: number
  includeSlackContext?: boolean
  claudeProjectsDir?: string
  heartbeatMs?: number
  onHeartbeat?: (info: HeartbeatInfo) => void | Promise<void>
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

interface ClaudeJsonlFallbackState {
  path: string
  lineCount: number
}

const DEFAULT_BASE_PORT = 3010
const DEFAULT_MAX_PORTS = 90
const DEFAULT_LOCK_TIMEOUT_MS = 10_000
const DEFAULT_LOCK_POLL_MS = 50
const DEFAULT_ACTIVATION_TIMEOUT_MS = 30_000
const DEFAULT_STATUS_POLL_MS = 1_000
const DEFAULT_FORWARD_TIMEOUT_MS = 15 * 60 * 1000
const DEFAULT_MESSAGE_SETTLE_MS = 750
const DEFAULT_HEARTBEAT_MS = 30_000
const DEFAULT_MESSAGE_SETTLE_POLL_MS = 250
// Window for retrying the transient "agent is not waiting for user input" POST
// race after a worker spawn/recycle. A freshly spawned Claude worker can take
// tens of seconds to load context/MCP before it reaches the input prompt, so
// this matches the activation-timeout magnitude rather than the old 5s, which
// was too short post-recycle (opshub#155, Phase 5 follow-up).
const DEFAULT_MESSAGE_POST_RETRY_TIMEOUT_MS = 30_000
const DEFAULT_MESSAGE_POST_RETRY_POLL_MS = 250
// Budget for re-polling /messages when it settles empty/context-only after the
// agent is stable. agentapi can briefly lag the final assistant text behind the
// stable status; re-polling recovers the real reply instead of falling back to a
// possibly-partial JSONL (opshub#155, Phase 5 follow-up).
const DEFAULT_REPLY_REPOLL_MS = 3_000
const SAFE_SESSION_KEY_RE = /^[A-Za-z0-9:._-]+$/
const ANSI_ESCAPE_RE = /\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1B\\))/g
const CONTROL_CHAR_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g
const TUI_PREFIX_RE = /^[ \t]*[●⏺]\s*/
const TUI_TIMED_STATUS_RE =
  /^[✻✶✱✢]\s+.*\bfor\s+\d+(?:\.\d+)?\s*(?:ms|s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours)\b/i
const TUI_TOOL_STATUS_RE = /^(?:Ran|Searched|Called)\b(?:\s|:|$)/
const TUI_TRANSIENT_STATUS_RE = /^[✻✶✱✢]?\s*(?:Ruminating|Thinking)(?:…|\.\.\.)(?:\s|$|\()/i
// Live Claude Code spinner status line ("✶ Ruminating… (51s · esc to interrupt)")
// and the gerund verb within it. Used by the progress heartbeat to surface the
// current visible status instead of a generic label (opshub#155, Phase 5).
const TUI_STATUS_GLYPH_RE = /^[✻✶✱✢]\s/
const HEARTBEAT_STATUS_VERB_RE = /[✻✶✱✢*]?\s*([A-Za-z][A-Za-z ]*?)\s*(?:…|\.{3})/
const SLACK_INBOUND_ECHO_RE = /^←\s*slack\s*·\s*/i
const SLACK_ECHO_CONTINUATION_RE = /^.{1,32}…$/
const CONTEXT_USAGE_RE = /^(\d+%)\s+context used$/i
const CONTEXT_USAGE_ANYWHERE_RE = /(\d+%)\s+context used/gi
const MARKDOWN_LINE_PREFIX_RE = /^([ \t]{0,3}(?:(?:[-*+]|\d+[.)])[ \t]+|>[ \t]?))/
const EXCESS_HORIZONTAL_SPACE_RE = /[ \t]{2,}/g
const CLAUDE_PROJECT_SAFE_CHAR_RE = /[^A-Za-z0-9_-]/g
const CLAUDE_SESSION_ALREADY_IN_USE_RE = /Error:\s+Session ID [0-9a-f-]+ is already in use\./i
const AGENT_WAITING_FOR_USER_INPUT_RE = /message can only be sent when the agent is waiting for user input/i
// Signatures of the Claude startup / setup / context-index TUI screen that a
// fresh worker shows before it has replied to the just-posted message. These
// survive sanitizeAgentReply, so we detect them to avoid posting them as a
// reply. Captured from a real worker .state file (opshub#155, Phase 5).
const STARTUP_ARTIFACT_RE =
  /SessionStart:|Settings Warning|\bsetup issues:|Context Index:|\$CMEM\b|❯\s*\d+\.\s|^[ \t]*[─━]{20,}[ \t]*$/m

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

export function claudeProjectSessionJsonlPath(
  cwd: string,
  sessionId: string,
  claudeProjectsDir = join(homedir(), '.claude', 'projects'),
): string {
  const projectName = resolve(cwd).replace(CLAUDE_PROJECT_SAFE_CHAR_RE, '-')
  return join(claudeProjectsDir, projectName, `${sessionId}.jsonl`)
}

export function buildAgentapiCommand(
  port: number,
  key: string,
  stateDir = defaultStateDir(),
  agentapiPath = join(homedir(), 'bin', 'agentapi'),
  options: BuildAgentapiCommandOptions = {},
): { command: string; args: string[]; stateFile: string; claudeSessionId: string } {
  const stateFile = stateFilePathForKey(stateDir, key)
  const claudeSessionId = claudeSessionIdForKey(key)
  const sessionJsonl = claudeProjectSessionJsonlPath(
    options.cwd || process.cwd(),
    claudeSessionId,
    options.claudeProjectsDir,
  )
  const sessionJsonlExists = options.sessionJsonlExists || existsSync
  const sessionArgs = sessionJsonlExists(sessionJsonl)
    ? ['--resume', claudeSessionId]
    : ['--session-id', claudeSessionId]

  // agentapi v0.12.2 rejects server-level --session-id. Claude accepts only
  // UUID session IDs, so the thread key is carried by the state file/name and
  // a deterministic UUID is used for Claude's session identity. Once Claude has
  // created the JSONL for that UUID, later starts must resume it instead.
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
      ...sessionArgs,
      '--name',
      key,
      '--model',
      'claude-opus-4-6[1m]',
      '--effort',
      'max',
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
  const forwardedContent = meta
    ? formatForwardedMessage(text, meta, {
      includeSlackContext: options.includeSlackContext ?? true,
    })
    : text
  const jsonlFallbackState = meta
    ? await captureClaudeJsonlFallbackState(meta, options)
    : undefined

  await postAgentMessageWithRetry(fetchImpl, `${baseUrl}/message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: forwardedContent, type: 'user' }),
  }, options)

  await waitForStable(port, options, options.onHeartbeat)

  let content = await waitForSettledAgentMessageContent(port, options)
  let sanitized = sanitizeAgentReply(content)

  // Post-settle flush race: status can report stable while agentapi /messages is
  // momentarily empty/context-only, or only a short header plus context footer,
  // before the final assistant text lands. Rather than immediately returning a
  // header-only "header\n\nN% context used" (the live opshub#155 signature),
  // re-poll /messages briefly for the real reply. Startup-artifact screens keep
  // their JSONL-fallback handling.
  const needsMessageRepoll = replyNeedsMessageRepoll(sanitized)
  if (needsMessageRepoll && !replyIsStartupArtifact(sanitized)) {
    const recovered = await repollMeaningfulAgentReply(port, options)
    if (recovered !== undefined) {
      content = recovered
      sanitized = sanitizeAgentReply(content)
    }
  }

  const contextUsageLine = latestContextUsageLine(content)
  // A fresh worker's first /messages snapshot can be the Claude startup /
  // context-index screen rather than a reply to the just-posted message. Treat
  // it (alongside empty/context-only content) as "no real reply yet" and prefer
  // the session JSONL, which is keyed to the posted message. Only when we have a
  // JSONL to fall back to, so a startup false-positive can never drop a reply.
  const isStartupArtifact = Boolean(jsonlFallbackState) && replyIsStartupArtifact(sanitized)
  if (!replyNeedsJsonlFallback(sanitized) && !replyLooksHeaderOnlyWithContext(sanitized) && !isStartupArtifact) {
    return sanitized
  }

  const jsonlContent = jsonlFallbackState
    ? await fetchLatestClaudeJsonlAssistantText(jsonlFallbackState)
    : undefined
  const sanitizedJsonl = jsonlContent ? sanitizeAgentReply(jsonlContent) : ''
  // Diagnostic (no secrets): a truncated delivery surfaces here as a fallback
  // path firing — e.g. agentapi /messages went empty/context-only and the JSONL
  // held only a partial assistant turn, yielding "header\n\nN% context used". Log
  // the lengths so a future mismatch is attributable to this path vs the
  // sanitizer or sendReplyToSlack (opshub#155, Phase 5 follow-up).
  console.error(
    `[slack] forwardMessage reply fallback (${isStartupArtifact ? 'startup-artifact' : 'agentapi-empty-or-context-only'}): ` +
      `raw /messages len=${content.length}, agentapi sanitized len=${sanitized.length}, jsonl len=${sanitizedJsonl.length}`,
  )
  if (sanitizedJsonl) return appendContextUsageLine(sanitizedJsonl, contextUsageLine)

  // No real reply from AgentAPI or the JSONL. Never post the raw startup /
  // context-index screen; surface the normalized context-usage line alone if we
  // have one, else empty (deliverToSession skips empty replies).
  if (isStartupArtifact) return contextUsageLine ?? ''
  return sanitized
}

async function captureClaudeJsonlFallbackState(
  meta: Record<string, string>,
  options: ThreadRouterOptions,
): Promise<ClaudeJsonlFallbackState | undefined> {
  try {
    const key = sessionKeyFromMeta(meta)
    const sessionId = claudeSessionIdForKey(key)
    const path = claudeProjectSessionJsonlPath(
      options.cwd || process.cwd(),
      sessionId,
      options.claudeProjectsDir,
    )
    return { path, lineCount: await countExistingJsonlLines(path) }
  } catch {
    return undefined
  }
}

async function countExistingJsonlLines(path: string): Promise<number> {
  try {
    const raw = await readFile(path, 'utf8')
    if (!raw) return 0
    return raw.endsWith('\n') ? raw.split('\n').length - 1 : raw.split('\n').length
  } catch (err) {
    if (err && typeof err === 'object' && 'code' in err && err.code === 'ENOENT') return 0
    throw err
  }
}

function replyNeedsJsonlFallback(reply: string): boolean {
  const trimmed = reply.trim()
  if (!trimmed) return true
  return trimmed.split('\n').every((line) => CONTEXT_USAGE_RE.test(line.trim()))
}

function replyNeedsMessageRepoll(reply: string): boolean {
  return replyNeedsJsonlFallback(reply) || replyLooksHeaderOnlyWithContext(reply)
}

function replyLooksHeaderOnlyWithContext(reply: string): boolean {
  const trimmed = reply.trim()
  if (!trimmed) return false

  const lines = trimmed.split('\n').map((line) => line.trim()).filter(Boolean)
  if (!lines.some((line) => CONTEXT_USAGE_RE.test(line))) return false

  const substantive = lines.filter((line) => !CONTEXT_USAGE_RE.test(line))
  if (substantive.length !== 1) return false

  const [header] = substantive
  // Keep this generic: a lone short non-context line followed by a context footer
  // is likely a prefix/header flush, while a long paragraph + context footer is a
  // valid concise answer and should not wait or fall back.
  return header.length <= 120 && trimmed.length <= 180
}

export function replyIsStartupArtifact(content: string): boolean {
  return STARTUP_ARTIFACT_RE.test(content)
}

function latestContextUsageLine(content: string): string | undefined {
  let latest: string | undefined
  CONTEXT_USAGE_ANYWHERE_RE.lastIndex = 0
  let match: RegExpExecArray | null
  while ((match = CONTEXT_USAGE_ANYWHERE_RE.exec(content)) !== null) {
    latest = `${match[1]} context used`
  }
  return latest
}

function appendContextUsageLine(reply: string, contextUsageLine: string | undefined): string {
  const trimmed = reply.trim()
  if (!contextUsageLine || !trimmed) return trimmed
  if (trimmed.split('\n').some((line) => line.trim() === contextUsageLine)) return trimmed
  return `${trimmed}\n\n${contextUsageLine}`
}

export interface HeartbeatInfo {
  // Raw current visible Claude Code TUI status line, if any (e.g. "✶ Ruminating…").
  status?: string
  // Raw or normalized context-usage text; the parseable figure is extracted.
  contextUsage?: string
}

// Text for the in-place progress heartbeat the main router shows while a thread
// worker is busy. Prefers the live TUI status verb (e.g. "Ruminating…"); falls
// back to a neutral terminal-style "Working…". Never emits "Thinking" and never
// echoes raw TUI content (no spam). Appends a normalized "N% context used" tail
// when a figure is parseable.
export function buildHeartbeatMessage(info: HeartbeatInfo = {}): string {
  const phrase = heartbeatStatusPhrase(info.status) ?? 'Working…'
  const match = info.contextUsage?.match(/(\d+%)\s+context used/i)
  return match ? `${phrase} · ${match[1]} context used` : phrase
}

function heartbeatStatusPhrase(status: string | undefined): string | undefined {
  if (!status) return undefined
  const verb = status.match(HEARTBEAT_STATUS_VERB_RE)?.[1]?.trim()
  if (!verb || /^thinking$/i.test(verb)) return undefined
  return `${verb}…`
}

async function fetchLatestClaudeJsonlAssistantText(
  state: ClaudeJsonlFallbackState,
): Promise<string | undefined> {
  let raw: string
  try {
    raw = await readFile(state.path, 'utf8')
  } catch (err) {
    if (err && typeof err === 'object' && 'code' in err && err.code === 'ENOENT') return undefined
    throw err
  }

  const lines = raw.split('\n').filter((line) => line.trim())
  let sawPostedUser = false
  let latestText: string | undefined

  for (const line of lines.slice(state.lineCount)) {
    let entry: unknown
    try {
      entry = JSON.parse(line)
    } catch {
      continue
    }
    if (!entry || typeof entry !== 'object') continue
    const record = entry as Record<string, unknown>

    if (record['type'] === 'user' && record['isMeta'] !== true) {
      sawPostedUser = true
      continue
    }
    if (!sawPostedUser || record['type'] !== 'assistant') continue

    const assistantText = extractClaudeAssistantText(record)
    if (assistantText && !isIgnoredClaudeAssistantText(assistantText)) latestText = assistantText
  }

  return latestText
}

function extractClaudeAssistantText(record: Record<string, unknown>): string {
  const message = record['message']
  if (!message || typeof message !== 'object') return ''
  const messageRecord = message as Record<string, unknown>
  if (messageRecord['model'] === '<synthetic>') return ''
  const content = messageRecord['content']
  if (typeof content === 'string') return content
  if (!Array.isArray(content)) return ''

  return content
    .map((part) => {
      if (!part || typeof part !== 'object') return ''
      const partRecord = part as Record<string, unknown>
      return partRecord['type'] === 'text' && typeof partRecord['text'] === 'string'
        ? partRecord['text']
        : ''
    })
    .filter((part) => part.trim())
    .join('\n')
}

function isIgnoredClaudeAssistantText(text: string): boolean {
  return /^no response requested\.?$/i.test(text.trim())
}

async function waitForSettledAgentMessageContent(
  port: number,
  options: ThreadRouterOptions,
): Promise<string> {
  const settleMs = Math.max(0, options.messageSettleMs ?? DEFAULT_MESSAGE_SETTLE_MS)
  const pollMs = Math.max(
    1,
    Math.min(options.statusPollMs || DEFAULT_STATUS_POLL_MS, DEFAULT_MESSAGE_SETTLE_POLL_MS),
  )
  // Overall ceiling so a worker that resumes and never settles can't wedge the
  // forward; reuses waitForStable's bound (opshub#155, Phase 5 follow-up).
  const overallDeadline = Date.now() + (options.forwardTimeoutMs || DEFAULT_FORWARD_TIMEOUT_MS)
  let settleDeadline = Date.now() + settleMs
  let previousContent: string | undefined
  let latestContent: string | undefined
  let hasPrevious = false

  while (true) {
    latestContent = await fetchLatestAgentMessageContent(port, options)
    // A worker that is still running can post mid-turn content during tool-call
    // pauses; unchanged content must not settle while it is busy, or the reply
    // gets truncated. Only count the settle window once status is stable.
    const running = (await getAgentStatus(port, options)) === 'running'

    if (running) {
      // Provisional mid-turn content: drop the unchanged-content tracking and
      // restart the settle window so a pause cannot post a partial reply.
      previousContent = undefined
      hasPrevious = false
      settleDeadline = Date.now() + settleMs
    } else if (
      latestContent !== undefined &&
      hasPrevious &&
      latestContent === previousContent
    ) {
      return latestContent
    } else {
      previousContent = latestContent
      hasPrevious = true
    }

    const now = Date.now()
    if (now >= overallDeadline) return latestContent || ''
    if (!running && (settleMs === 0 || now >= settleDeadline)) return latestContent || ''
    const cap = running ? overallDeadline : settleDeadline
    await sleep(Math.min(pollMs, Math.max(1, cap - now)))
  }
}

async function fetchLatestAgentMessageContent(
  port: number,
  options: ThreadRouterOptions,
): Promise<string | undefined> {
  const fetchImpl = options.fetch || fetch
  const body = await fetchJson<MessagesBody>(fetchImpl, `http://127.0.0.1:${port}/messages`)
  const agentMessages = (body.messages || []).filter(
    (message) => message.role === 'agent' && typeof message.content === 'string',
  )
  return agentMessages.at(-1)?.content
}

// After the agent is stable but /messages settled empty/context-only, re-poll
// briefly for a real reply (a flush race). Returns the raw /messages content once
// it sanitizes to a real reply (non-fallback, non-startup-artifact), or undefined
// if the budget expires — in which case the caller keeps its existing JSONL /
// context-only fallback (opshub#155, Phase 5 follow-up).
async function repollMeaningfulAgentReply(
  port: number,
  options: ThreadRouterOptions,
): Promise<string | undefined> {
  const budgetMs = Math.max(0, options.replyRepollMs ?? DEFAULT_REPLY_REPOLL_MS)
  if (budgetMs === 0) return undefined
  const pollMs = Math.max(
    1,
    Math.min(options.statusPollMs || DEFAULT_STATUS_POLL_MS, DEFAULT_MESSAGE_SETTLE_POLL_MS),
  )
  const now = options.now || Date.now
  const deadline = now() + budgetMs

  while (now() < deadline) {
    await sleep(Math.min(pollMs, Math.max(1, deadline - now())))
    const content = await fetchLatestAgentMessageContent(port, options)
    if (content === undefined) continue
    const sanitized = sanitizeAgentReply(content)
    if (!replyNeedsMessageRepoll(sanitized) && !replyIsStartupArtifact(sanitized)) {
      return content
    }
  }
  return undefined
}

export function sanitizeAgentReply(content: string): string {
  content = scopeToLatestSlackInboundEcho(content)

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
        TUI_TOOL_STATUS_RE.test(trimmed) ||
        TUI_TRANSIENT_STATUS_RE.test(trimmed))
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

function scopeToLatestSlackInboundEcho(content: string): string {
  const lines = content.replace(/\r\n?/g, '\n').split('\n')
  let latestEchoIndex = -1
  let inFence = false
  let fenceMarker = ''

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]!.replace(ANSI_ESCAPE_RE, '').replace(CONTROL_CHAR_RE, '').trimEnd()
    const trimmedStart = line.trimStart()
    const fence = trimmedStart.match(/^(```+|~~~+)/)?.[1]

    if (inFence) {
      if (fence && fence[0] === fenceMarker[0] && fence.length >= fenceMarker.length) {
        inFence = false
        fenceMarker = ''
      }
      continue
    }

    if (fence) {
      inFence = true
      fenceMarker = fence
      continue
    }

    if (SLACK_INBOUND_ECHO_RE.test(line.replace(TUI_PREFIX_RE, '').trim())) {
      latestEchoIndex = index
    }
  }

  if (latestEchoIndex < 0) return content

  const afterEcho = latestEchoIndex + 1
  const blankAfterEchoIndex = lines.findIndex((rawLine, index) => {
    if (index < afterEcho) return false
    const line = rawLine.replace(ANSI_ESCAPE_RE, '').replace(CONTROL_CHAR_RE, '').trimEnd()
    return !line.replace(TUI_PREFIX_RE, '').trim()
  })

  if (blankAfterEchoIndex > afterEcho && blankAfterEchoIndex - afterEcho >= 2) {
    const beforeBlankLooksLikeEchoContinuation = lines.slice(afterEcho, blankAfterEchoIndex).every((rawLine) => {
      const line = rawLine.replace(ANSI_ESCAPE_RE, '').replace(CONTROL_CHAR_RE, '').trimEnd()
      const trimmed = line.replace(TUI_PREFIX_RE, '').trim()
      return Boolean(trimmed) && !TUI_PREFIX_RE.test(line) && !CONTEXT_USAGE_RE.test(trimmed)
    })
    if (beforeBlankLooksLikeEchoContinuation) {
      return lines.slice(blankAfterEchoIndex + 1).join('\n')
    }
  }

  let start = afterEcho
  while (start < lines.length) {
    const line = lines[start]!.replace(ANSI_ESCAPE_RE, '').replace(CONTROL_CHAR_RE, '').trimEnd()
    const trimmed = line.replace(TUI_PREFIX_RE, '').trim()
    if (!trimmed) {
      start += 1
      break
    }
    if (!SLACK_ECHO_CONTINUATION_RE.test(trimmed)) break
    start += 1
  }

  return lines.slice(start).join('\n')
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

export async function reapFakeActiveSessions(
  options: ThreadRouterOptions = {},
): Promise<string[]> {
  const stateDir = options.stateDir || defaultStateDir()
  const now = options.now || Date.now

  return withRegistryLock(stateDir, async () => {
    const registry = await readRegistryFile(registryFilePath(stateDir))
    const reaped: string[] = []

    for (const [key, session] of Object.entries(registry)) {
      if (session.status !== 'active' && session.status !== 'activating') continue
      if (!(await isFakeActiveSession(session, options))) continue
      registry[key] = {
        ...session,
        pid: 0,
        status: 'dead',
        last_active_at: new Date(now()).toISOString(),
      }
      reaped.push(key)
    }

    if (reaped.length) {
      await writeRegistryAtomic(registryFilePath(stateDir), registry)
    }
    return reaped
  })
}

// A session is fake-active when its registry status claims active/activating
// but the worker is gone: a recorded pid that is no longer alive, or — for an
// already-active session — a port nothing is listening on (a free/bindable port
// means the agentapi released it). Activating sessions skip the port probe:
// their agentapi may not have bound the port yet.
async function isFakeActiveSession(
  session: ThreadSession,
  options: ThreadRouterOptions,
): Promise<boolean> {
  if (session.pid > 0 && !isPidAlive(session.pid, options)) return true
  if (session.status === 'active') {
    const portIsAvailable = options.portIsAvailable || defaultPortIsAvailable
    if (await portIsAvailable(session.port)) return true
  }
  return false
}

async function ensureSessionUnshared(
  key: string,
  options: ThreadRouterOptions,
  stateDir: string,
): Promise<ThreadSession> {
  await reapFakeActiveSessions({ ...options, stateDir })
  const existing = await readRegistry(stateDir).then((registry) => registry[key])
  if (existing?.status === 'active') {
    if (await isThreadSessionHealthy(key, existing, options, stateDir)) {
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
    if (await isThreadSessionHealthy(key, claim, options, stateDir)) {
      return touchSession(key, claim, options, stateDir)
    }
    await markDeadIfCurrent(key, claim, options, stateDir)
    return activateSession(key, options, stateDir)
  }
  if (claim.status !== 'activating') {
    return waitForActivation(key, options, stateDir)
  }

  const cwd = options.cwd || process.cwd()
  const agentapiPath = options.agentapiPath || join(homedir(), 'bin', 'agentapi')
  const { command, args } = buildAgentapiCommand(claim.port, key, stateDir, agentapiPath, { cwd })
  const spawnAgent = options.spawnAgent || defaultSpawnAgent

  try {
    await mkdir(join(stateDir, 'sessions'), { recursive: true, mode: 0o700 })
    await unlinkFatalStartupStateFile(stateDir, key)
    const child = spawnAgent(command, args, {
      cwd,
      detached: true,
      stdio: 'ignore',
      env: {
        ...process.env,
        CLAUDE_AUTOCOMPACT_PCT_OVERRIDE: '0.80',
      },
    })
    child.unref?.()
    const pid = child.pid || 0
    await waitForAgentHealthy(claim.port, options, key, stateDir)
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
    if (session.status === 'active') {
      if (await isThreadSessionHealthy(key, session, options, stateDir)) {
        return touchSession(key, session, options, stateDir)
      }
      await markDeadIfCurrent(key, session, options, stateDir)
      return activateSession(key, options, stateDir)
    }
    await sleep(pollMs)
  }

  throw new Error(`Timed out waiting for thread session activation: ${key}`)
}

async function waitForAgentHealthy(
  port: number,
  options: ThreadRouterOptions,
  key?: string,
  stateDir?: string,
): Promise<void> {
  const deadline = Date.now() + (options.activationTimeoutMs || DEFAULT_ACTIVATION_TIMEOUT_MS)
  const pollMs = options.statusPollMs || DEFAULT_STATUS_POLL_MS

  while (Date.now() <= deadline) {
    if (
      await isAgentHealthy(port, options) &&
      (!key || !stateDir || !await hasFatalStartupStateFile(stateDir, key))
    ) return
    await sleep(pollMs)
  }

  throw new Error(`Timed out waiting for agentapi on port ${port}`)
}

async function waitForStable(
  port: number,
  options: ThreadRouterOptions,
  onHeartbeat?: (info: HeartbeatInfo) => void | Promise<void>,
): Promise<void> {
  const deadline = Date.now() + (options.forwardTimeoutMs || DEFAULT_FORWARD_TIMEOUT_MS)
  const pollMs = options.statusPollMs || DEFAULT_STATUS_POLL_MS
  const heartbeatMs = Math.max(0, options.heartbeatMs ?? DEFAULT_HEARTBEAT_MS)
  let nextHeartbeatAt = 0

  while (Date.now() <= deadline) {
    const status = await getAgentStatus(port, options)
    if (status === 'stable') return
    // status === 'running': emit a rate-limited progress heartbeat. The first
    // running poll fires immediately (liveness); later ones are throttled to
    // heartbeatMs. Best-effort context usage; failures never break the wait.
    if (onHeartbeat) {
      const at = Date.now()
      if (at >= nextHeartbeatAt) {
        nextHeartbeatAt = at + heartbeatMs
        const info = await currentHeartbeatInfo(port, options)
        void Promise.resolve(onHeartbeat(info)).catch(() => {})
      }
    }
    await sleep(pollMs)
  }

  throw new Error(`Timed out waiting for agentapi to become stable on port ${port}`)
}

async function currentHeartbeatInfo(
  port: number,
  options: ThreadRouterOptions,
): Promise<HeartbeatInfo> {
  try {
    const content = await fetchLatestAgentMessageContent(port, options)
    if (!content) return {}
    return { status: latestStatusLine(content), contextUsage: latestContextUsageLine(content) }
  } catch {
    return {}
  }
}

function latestStatusLine(content: string): string | undefined {
  let latest: string | undefined
  for (const raw of content.replace(/\r\n?/g, '\n').split('\n')) {
    const line = raw.replace(ANSI_ESCAPE_RE, '').replace(CONTROL_CHAR_RE, '').trim()
    if (TUI_STATUS_GLYPH_RE.test(line)) latest = line
  }
  return latest
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

async function isThreadSessionHealthy(
  key: string,
  session: ThreadSession,
  options: ThreadRouterOptions,
  stateDir: string,
): Promise<boolean> {
  if (session.pid > 0 && !isPidAlive(session.pid, options)) return false
  if (await hasFatalStartupStateFile(stateDir, key)) return false
  return isAgentHealthy(session.port, options)
}

function isPidAlive(pid: number, options: ThreadRouterOptions): boolean {
  return (options.pidIsAlive || defaultPidIsAlive)(pid)
}

async function hasFatalStartupStateFile(stateDir: string, key: string): Promise<boolean> {
  const path = stateFilePathForKey(stateDir, key)
  try {
    const raw = await readFile(path, 'utf8')
    const parsed = JSON.parse(raw) as unknown
    if (!parsed || typeof parsed !== 'object') return false
    const messages = (parsed as { messages?: unknown }).messages
    if (!Array.isArray(messages) || messages.length === 0) return false
    const hasUserMessage = messages.some((message) =>
      Boolean(message && typeof message === 'object' && (message as { role?: unknown }).role === 'user'),
    )
    if (hasUserMessage) return false
    return messages.some((message) =>
      Boolean(
        message &&
        typeof message === 'object' &&
        (message as { role?: unknown }).role === 'agent' &&
        typeof (message as { message?: unknown }).message === 'string' &&
        CLAUDE_SESSION_ALREADY_IN_USE_RE.test((message as { message: string }).message),
      ),
    )
  } catch {
    return false
  }
}

async function unlinkFatalStartupStateFile(stateDir: string, key: string): Promise<void> {
  if (!await hasFatalStartupStateFile(stateDir, key)) return
  try {
    await unlink(stateFilePathForKey(stateDir, key))
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err
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

// agentapi itself gates POST /message on the agent being ready for input (it
// returns the "waiting for user input" 500 otherwise), so that gate — not a
// /status read — is the authoritative readiness signal. (/status `stable` flips
// transiently and is an unreliable proxy; see waitForSettledAgentMessageContent.)
// We therefore wait for readiness by retrying the POST against agentapi's own
// gate, bounded by messagePostRetryMs (opshub#155, Phase 5 follow-up).
async function postAgentMessageWithRetry<T>(
  fetchImpl: (input: string, init?: RequestInit) => Promise<Response>,
  url: string,
  init: RequestInit,
  options: ThreadRouterOptions,
): Promise<T> {
  const now = options.now || Date.now
  const retryMs = Math.max(0, options.messagePostRetryMs ?? DEFAULT_MESSAGE_POST_RETRY_TIMEOUT_MS)
  const deadline = now() + retryMs
  const pollMs = Math.max(
    1,
    Math.min(options.statusPollMs || DEFAULT_MESSAGE_POST_RETRY_POLL_MS, DEFAULT_MESSAGE_POST_RETRY_POLL_MS),
  )

  while (true) {
    const response = await fetchImpl(url, init)
    const rawBody = await response.text()
    if (response.ok) {
      return (rawBody ? JSON.parse(rawBody) : {}) as T
    }

    const isTransientStartupRace =
      response.status === 500 && AGENT_WAITING_FOR_USER_INPUT_RE.test(rawBody)
    const remainingMs = deadline - now()
    if (!isTransientStartupRace || remainingMs <= 0) {
      const detail = rawBody.trim() ? `: ${rawBody.trim()}` : ''
      throw new Error(`agentapi request failed: ${response.status} ${response.statusText}${detail}`)
    }

    await sleep(Math.min(pollMs, remainingMs))
  }
}

function defaultSpawnAgent(
  command: string,
  args: string[],
  options: { cwd: string; detached: true; stdio: 'ignore'; env: NodeJS.ProcessEnv },
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

function defaultPidIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code
    if (code === 'ESRCH') return false
    if (code === 'EPERM') return true
    return false
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
