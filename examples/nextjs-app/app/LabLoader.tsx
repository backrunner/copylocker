'use client'

import dynamic from 'next/dynamic'

// The real SDK requires a browser (wasm, WebCrypto, IndexedDB); keep it out
// of the server render entirely. The SSR stub in page.tsx covers the server
// pass (design §4.5, FR-WEB-009).
const CopyLockerLab = dynamic(() => import('./CopyLockerLab'), {
  ssr: false,
  loading: () => <p data-testid="lab-loading">Loading CopyLocker SDK…</p>,
})

export default function LabLoader() {
  return <CopyLockerLab />
}
