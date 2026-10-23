// Decrypted content and the non-extractable key stay in memory, scoped to a tab.
const root = new URL('./', self.location.href)
const sessions = new Map()
const chunks = new Map()
let cacheBytes = 0
const cacheLimit = 20 * 1024 * 1024
self.addEventListener('install', () => self.skipWaiting())
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()))
self.addEventListener('message', event => {
  if (event.data?.type === 'esite-lock' && event.source?.id) { sessions.delete(event.source.id); return }
  if (event.data?.type !== 'esite-unlock' || !event.source?.id || !event.data.key || !event.data.manifest) return
  sessions.set(event.source.id, { key: event.data.key, manifest: event.data.manifest })
  event.ports[0]?.postMessage({ ok: true })
  void self.clients.matchAll().then(clients => { const ids = new Set(clients.map(client => client.id)); for (const id of sessions.keys()) if (!ids.has(id)) sessions.delete(id) })
})
async function sessionFor(id) {
  if (sessions.has(id)) return sessions.get(id)
  const client = await self.clients.get(id)
  if (!client) return null
  return new Promise(resolve => {
    const channel = new MessageChannel()
    const timer = setTimeout(() => { channel.port1.close(); resolve(null) }, 4000)
    channel.port1.onmessage = event => {
      clearTimeout(timer); channel.port1.close()
      const state = event.data
      if (state?.key && state?.manifest) { sessions.set(id, state); resolve(state) } else resolve(null)
    }
    client.postMessage({ type: 'esite-session' }, [channel.port2])
  })
}
async function decryptChunk(state, file, index) {
  const id = file.chunks[index]
  if (!/^[a-f0-9]{32}$/.test(id)) throw new Error('Invalid asset')
  let payload = chunks.get(id)
  if (!payload) {
    const response = await fetch(new URL('sealed/' + id + '.bin', root))
    if (!response.ok) throw new Error('Asset unavailable')
    payload = new Uint8Array(await response.arrayBuffer())
    if (chunks.has(id)) { cacheBytes -= chunks.get(id).byteLength; chunks.delete(id) }
    while (cacheBytes + payload.byteLength > cacheLimit && chunks.size) { const first = chunks.keys().next().value; cacheBytes -= chunks.get(first).byteLength; chunks.delete(first) }
    chunks.set(id, payload); cacheBytes += payload.byteLength
  } else { chunks.delete(id); chunks.set(id, payload) }
  // Only ciphertext is shared. Every request must authenticate with its own key.
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: payload.slice(0, 12), additionalData: new TextEncoder().encode(file.path + '#' + index) }, state.key, payload.slice(12)))
}
async function respond(event, path) {
  const state = await sessionFor(event.clientId)
  if (!state) return new Response('Locked', { status: 401, headers: { 'Cache-Control': 'no-store' } })
  const file = state.manifest.files[path]
  if (!file) return new Response('Not found', { status: 404 })
  const range = event.request.headers.get('range')
  let start = 0, end = file.size - 1, status = 200
  if (range) {
    const match = /^bytes=(\d*)-(\d*)$/.exec(range)
    if (!match || !match[1] && !match[2]) return new Response(null, { status: 416 })
    if (!match[1]) start = Math.max(0, file.size - Number(match[2]))
    else { start = Number(match[1]); if (match[2]) end = Math.min(end, Number(match[2])) }
    if (start > end || start >= file.size) return new Response(null, { status: 416, headers: { 'Content-Range': 'bytes */' + file.size } })
    status = 206
  }
  const headers = { 'Content-Type': file.type, 'Content-Length': String(end - start + 1), 'Accept-Ranges': 'bytes', 'Cache-Control': 'no-store' }
  if (status === 206) headers['Content-Range'] = `bytes ${start}-${end}/${file.size}`
  let firstChunk
  try { firstChunk = await decryptChunk(state, file, Math.floor(start / state.manifest.chunkSize)) }
  catch { return new Response('Unable to open asset', { status: 403, headers: { 'Cache-Control': 'no-store' } }) }
  let cursor = start, cancelled = false
  const stream = new ReadableStream({
    async pull(controller) {
      if (cancelled) return
      try {
        const index = Math.floor(cursor / state.manifest.chunkSize)
        const bytes = firstChunk || await decryptChunk(state, file, index)
        firstChunk = null
        if (cancelled) return
        const offset = cursor % state.manifest.chunkSize
        const count = Math.min(bytes.length - offset, end - cursor + 1)
        controller.enqueue(bytes.slice(offset, offset + count)); cursor += count
        if (cursor > end) controller.close()
      } catch (error) { if (!cancelled) controller.error(error) }
    }, cancel() { cancelled = true },
  })
  return new Response(stream, { status, headers })
}
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url)
  if (url.origin !== root.origin || !url.pathname.startsWith(root.pathname)) return
  const path = url.pathname.slice(root.pathname.length)
  // Navigations always return the gate, never an unlocked app from another tab.
  if (event.request.mode === 'navigate') { event.respondWith(fetch(new URL('index.html', root), { cache: 'no-store' })); return }
  if (path.startsWith('assets/') || path.startsWith('media/') || path === 'favicon.svg' || path === 'e-site-logo.svg') event.respondWith(respond(event, path))
})
