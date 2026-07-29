import {
  activate,
  challenge,
  deactivate,
  importOlk,
  offlineImport,
  offlineRequest,
  onStateChanged,
  state,
  unseal,
  type StateDto,
} from '@copylocker/tauri'

import './style.css'

const activity = requireElement<HTMLOutputElement>('activity')
const stateName = requireElement<HTMLElement>('state-name')
const stateDetail = requireElement<HTMLElement>('state-detail')
const stateDot = requireElement<HTMLElement>('state-dot')

function requireElement<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id)
  if (!element) throw new Error(`Missing element ${id}`)
  return element as T
}

function report(message: string): void {
  activity.value = message
}

function reportError(error: unknown): void {
  const code = (error as { code?: unknown } | null)?.code
  report(`Failed / ${Number.isSafeInteger(code) ? code : 3999}`)
}

function renderState(value: StateDto): void {
  stateName.textContent = value.state.replaceAll('_', ' ')
  stateDetail.textContent = value.state.replaceAll('_', ' ')
  stateDot.dataset.state = value.state
}

async function refreshState(): Promise<void> {
  try {
    renderState(await state())
  } catch (error) {
    reportError(error)
  }
}

function download(bytes: Uint8Array, filename: string): void {
  const url = URL.createObjectURL(new Blob([bytes as BlobPart]))
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.click()
  URL.revokeObjectURL(url)
}

document.querySelectorAll<HTMLButtonElement>('.tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((candidate) => candidate.classList.remove('active'))
    document.querySelectorAll<HTMLElement>('.tab-panel').forEach((panel) => {
      const active = panel.dataset.panel === tab.dataset.tab
      panel.classList.toggle('active', active)
      panel.hidden = !active
    })
    tab.classList.add('active')
  })
})

requireElement<HTMLFormElement>('activate-form').addEventListener('submit', async (event) => {
  event.preventDefault()
  const key = requireElement<HTMLInputElement>('license-key').value.trim()
  report('Activating')
  try {
    await activate(key)
    report('Activated')
    await refreshState()
  } catch (error) {
    reportError(error)
  }
})

requireElement<HTMLButtonElement>('deactivate').addEventListener('click', async () => {
  report('Deactivating')
  try {
    await deactivate()
    report('Deactivated')
    await refreshState()
  } catch (error) {
    reportError(error)
  }
})

requireElement<HTMLButtonElement>('offline-request').addEventListener('click', async () => {
  const key = requireElement<HTMLInputElement>('license-key').value.trim()
  try {
    download(await offlineRequest(key), 'copylocker-request.cbor')
    report('Offline request exported')
  } catch (error) {
    reportError(error)
  }
})

requireElement<HTMLInputElement>('offline-import').addEventListener('change', async (event) => {
  const file = (event.currentTarget as HTMLInputElement).files?.[0]
  if (!file) return
  try {
    await offlineImport(new Uint8Array(await file.arrayBuffer()))
    report('Offline response imported')
    await refreshState()
  } catch (error) {
    reportError(error)
  }
})

requireElement<HTMLInputElement>('olk-import').addEventListener('change', async (event) => {
  const file = (event.currentTarget as HTMLInputElement).files?.[0]
  if (!file) return
  try {
    await importOlk(await file.text())
    report('OLK imported')
    await refreshState()
  } catch (error) {
    reportError(error)
  }
})

requireElement<HTMLFormElement>('unseal-form').addEventListener('submit', async (event) => {
  event.preventDefault()
  const file = requireElement<HTMLInputElement>('sealed-file').files?.[0]
  if (!file) return
  try {
    const feature = requireElement<HTMLInputElement>('feature').value.trim()
    download(
      await unseal(feature, new Uint8Array(await file.arrayBuffer())),
      file.name.replace(/\.sealed$/, '') || 'unsealed.bin',
    )
    report('Asset unsealed')
  } catch (error) {
    reportError(error)
  }
})

requireElement<HTMLFormElement>('challenge-form').addEventListener('submit', async (event) => {
  event.preventDefault()
  const file = requireElement<HTMLInputElement>('challenge-file').files?.[0]
  if (!file) return
  try {
    download(
      await challenge(new Uint8Array(await file.arrayBuffer())),
      'copylocker-response.cbor',
    )
    report('Challenge answered')
  } catch (error) {
    reportError(error)
  }
})

void refreshState()
void onStateChanged(renderState).catch(reportError)
