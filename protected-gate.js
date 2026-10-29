const base = '/esite/'
const root = new URL(base, location.origin)
const form = document.querySelector('#entry-form'), field = document.querySelector('#entry-password'), username = document.querySelector('#entry-username'), button = document.querySelector('#entry-submit'), status = document.querySelector('#entry-status')
let session = null
const gateNodes = [...document.body.childNodes], gateStyle = document.querySelector('#esite-gate-style')
const appLinks = []
navigator.serviceWorker?.controller?.postMessage({ type: 'esite-lock' })
navigator.serviceWorker?.addEventListener('message', event => {
  if (event.data?.type === 'esite-session') event.ports[0]?.postMessage(session)
})
function waitForControl() {
  if (navigator.serviceWorker.controller) return Promise.resolve()
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { navigator.serviceWorker.removeEventListener('controllerchange', ready); reject(new Error('worker')) }, 15000)
    const ready = () => { clearTimeout(timer); navigator.serviceWorker.removeEventListener('controllerchange', ready); resolve() }
    navigator.serviceWorker.addEventListener('controllerchange', ready)
  })
}
async function openSite(manifest, key) {
  session = { manifest, key }
  const registration = await navigator.serviceWorker.register(new URL('protected-worker.js', root), { scope: base, updateViaCache: 'none' })
  await navigator.serviceWorker.ready
  await waitForControl()
  await new Promise((resolve, reject) => {
    const channel = new MessageChannel()
    const timer = setTimeout(() => { channel.port1.close(); reject(new Error('worker')) }, 10000)
    channel.port1.onmessage = () => { clearTimeout(timer); channel.port1.close(); resolve() }
    ;(registration.active || navigator.serviceWorker.controller).postMessage({ type: 'esite-unlock', ...session }, [channel.port2])
  })
  const doc = new DOMParser().parseFromString(manifest.html, 'text/html')
  document.title = doc.title
  // Apply the explicit visitor choice before the app CSS can paint its first frame.
  let theme = 'night'
  try { if (localStorage.getItem('esite-theme-choice') === 'day') theme = 'day' } catch {}
  document.documentElement.dataset.theme = theme
  document.documentElement.style.colorScheme = theme === 'night' ? 'dark' : 'light'
  document.querySelector('meta[name="color-scheme"]')?.setAttribute('content', theme === 'night' ? 'dark' : 'light')
  const loaded = []
  for (const link of doc.head.querySelectorAll('link[rel="stylesheet"],link[rel="icon"]')) {
    const clone = link.cloneNode(true)
    appLinks.push(clone)
    if (clone.rel === 'stylesheet') loaded.push(new Promise((resolve, reject) => { clone.onload = resolve; clone.onerror = reject }))
    document.head.append(clone)
  }
  await Promise.all(loaded)
  document.querySelector('#esite-gate-style')?.remove()
  document.body.replaceChildren(...doc.body.querySelectorAll('#root'))
  const entry = doc.querySelector('script[type="module"][src]')?.getAttribute('src')
  if (!entry) throw new Error('entry')
  await import(new URL(entry, root).href)
}
form.addEventListener('submit', async event => {
  event.preventDefault(); if (button.disabled) return
  if (!crypto?.subtle || !navigator.serviceWorker || typeof DecompressionStream === 'undefined') { status.textContent = 'Otwórz stronę w aktualnej wersji Chrome, Safari, Firefox lub Edge.'; return }
  button.disabled = true; field.disabled = true; username.disabled = true; delete status.dataset.error; status.textContent = 'Otwieramy stronę…'
  let password = field.value; const login = username.value.trim(); field.value = ''
  try {
    const response = await fetch(new URL('payload.bin', root), { cache: 'no-store' })
    if (!response.ok) throw new Error('network')
    const buffer = await response.arrayBuffer(), raw = new Uint8Array(buffer), header = raw.slice(0, 40)
    if (new TextDecoder().decode(header.slice(0, 8)) !== 'ESITE03\0') throw new Error('format')
    const iterations = new DataView(buffer).getUint32(8, false)
    if (iterations !== 600000) throw new Error('format')
    const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(login + '\0' + password), 'PBKDF2', false, ['deriveKey']); password = ''
    const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: header.slice(12, 28), iterations, hash: 'SHA-256' }, material, { name: 'AES-GCM', length: 256 }, false, ['decrypt'])
    const packed = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: header.slice(28, 40), additionalData: header }, key, raw.slice(40))
    const manifest = JSON.parse(await new Response(new Blob([packed]).stream().pipeThrough(new DecompressionStream('gzip'))).text())
    await openSite(manifest, key)
  } catch (error) {
    password = ''; session = null
    document.documentElement.dataset.theme = 'night'
    document.documentElement.style.colorScheme = 'dark'
    document.querySelector('meta[name="color-scheme"]')?.setAttribute('content', 'dark')
    navigator.serviceWorker?.controller?.postMessage({ type: 'esite-lock' })
    if (!document.body.contains(form)) document.body.replaceChildren(...gateNodes)
    if (!gateStyle.isConnected) document.head.append(gateStyle)
    for (const link of appLinks.splice(0)) link.remove()
    status.textContent = error?.name === 'OperationError' ? 'Nieprawidłowy login lub hasło. Spróbuj ponownie.' : 'Nie udało się otworzyć strony. Odśwież i spróbuj ponownie.'
    status.dataset.error = ''; button.disabled = false; field.disabled = false; username.disabled = false; field.focus()
  }
})
