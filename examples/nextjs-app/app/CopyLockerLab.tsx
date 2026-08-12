'use client'

/**
 * Client-only CopyLocker demo, mirroring the vite-spa example: create (with
 * Worker isolation), activate / deactivate, advisory state badge, and
 * fetch-and-unseal of the web v1 demo asset.
 */

import { useEffect, useRef, useState } from 'react'
import { CopyLocker, type LicenseState } from '@copylocker/web'
import { copyLockerOptions } from '../lib/config'

export default function CopyLockerLab() {
  const clientRef = useRef<CopyLocker | null>(null)
  const [ready, setReady] = useState(false)
  const [initError, setInitError] = useState<string | null>(null)
  const [state, setState] = useState<LicenseState>('unlicensed')
  const [log, setLog] = useState<string[]>([])
  const [licenseKey, setLicenseKey] = useState('')
  const [featureId, setFeatureId] = useState('demo-feature')
  const [unseal, setUnseal] = useState<{ kind: 'ok' | 'error' | 'pending'; text: string }>({
    kind: 'pending',
    text: '—',
  })

  const appendLog = (message: string) =>
    setLog((prev) => [`${new Date().toISOString().slice(11, 19)} ${message}`, ...prev])

  useEffect(() => {
    let cancelled = false
    let cl: CopyLocker | null = null
    ;(async () => {
      try {
        cl = await CopyLocker.create({
          ...copyLockerOptions,
          // Glue + wasm are served from public/copylocker-wasm/ (see
          // scripts/copy-wasm.mjs) so dev and `next start` behave identically.
          glueBaseUrl: new URL('./copylocker-wasm/', window.location.href),
          onStateChange: (s) => {
            if (cancelled) return
            setState(s)
            appendLog(`state → ${s} (advisory)`)
          },
        })
      } catch (error) {
        if (!cancelled) {
          setInitError((error as Error).message)
          appendLog(`create failed: ${(error as Error).message}`)
        }
        return
      }
      if (cancelled) {
        cl.dispose()
        return
      }
      clientRef.current = cl
      if (cl.degradedFlags.storage) appendLog('degraded: IndexedDB unavailable (in-memory store)')
      if (cl.degradedFlags.worker) appendLog('degraded: Worker isolation inactive (main-thread core)')
      setState(cl.state)
      setReady(true)
    })()
    return () => {
      cancelled = true
      cl?.dispose()
      clientRef.current = null
    }
  }, [])

  const onActivate = async (event: React.FormEvent) => {
    event.preventDefault()
    const cl = clientRef.current
    if (!cl) return
    appendLog('activate…')
    try {
      await cl.activate(licenseKey.trim())
      appendLog('activate ok')
    } catch (error) {
      appendLog(`activate failed: ${(error as Error).message}`)
    }
  }

  const onDeactivate = async () => {
    const cl = clientRef.current
    if (!cl) return
    appendLog('deactivate…')
    try {
      await cl.deactivate()
      appendLog('deactivate ok')
    } catch (error) {
      appendLog(`deactivate failed: ${(error as Error).message}`)
    }
  }

  const onUnseal = async (event: React.FormEvent) => {
    event.preventDefault()
    const cl = clientRef.current
    if (!cl) return
    setUnseal({ kind: 'pending', text: 'unsealing…' })
    try {
      const bytes = await cl.loadSealed('/demo-asset.clx', featureId.trim())
      setUnseal({ kind: 'ok', text: new TextDecoder().decode(bytes) })
      appendLog(`unseal ok (${bytes.byteLength} bytes)`)
    } catch (error) {
      // NotEntitledError / UnsealError / TransportError — this failure, not
      // the advisory state, is the entitlement signal.
      const err = error as Error
      setUnseal({ kind: 'error', text: `${err.name}: ${err.message}` })
      appendLog(`unseal failed: ${err.message}`)
    }
  }

  return (
    <>
      <section className="panel" aria-label="Activation">
        <h2>License operations (client)</h2>
        <p className="meta">
          SDK{' '}
          <span data-testid="sdk-status" data-ready={ready}>
            {ready ? 'ready' : initError ? `error: ${initError}` : 'initializing…'}
          </span>{' '}
          · advisory state{' '}
          <code data-testid="license-state" title="Advisory only — never gate features on this value">
            {state}
          </code>{' '}
          <em className="advisory-tag">advisory only</em>
        </p>
        <form className="row" onSubmit={onActivate}>
          <label htmlFor="license-key">License key</label>
          <input
            id="license-key"
            autoComplete="off"
            placeholder="CL-XXXX-…"
            required
            value={licenseKey}
            onChange={(e) => setLicenseKey(e.target.value)}
            data-testid="license-key-input"
          />
          <button type="submit" disabled={!ready} data-testid="activate-button">
            Activate
          </button>
          <button
            type="button"
            className="quiet"
            disabled={!ready}
            onClick={onDeactivate}
            data-testid="deactivate-button"
          >
            Deactivate
          </button>
        </form>
      </section>

      <section className="panel" aria-label="Sealed asset">
        <h2>Sealed asset</h2>
        <form className="row" onSubmit={onUnseal}>
          <label htmlFor="feature-id">Feature</label>
          <input
            id="feature-id"
            required
            value={featureId}
            onChange={(e) => setFeatureId(e.target.value)}
            data-testid="feature-id-input"
          />
          <button type="submit" disabled={!ready} data-testid="unseal-button">
            Fetch &amp; unseal <code>/demo-asset.clx</code>
          </button>
        </form>
        <pre className="output" data-testid="unseal-output" data-kind={unseal.kind} aria-live="polite">
          {unseal.text}
        </pre>
      </section>

      <footer className="panel" aria-label="Activity log">
        <h2>Activity</h2>
        <ul className="log" data-testid="status-log" aria-live="polite">
          {log.map((entry, i) => (
            <li key={`${i}-${entry}`}>{entry}</li>
          ))}
        </ul>
      </footer>
    </>
  )
}
