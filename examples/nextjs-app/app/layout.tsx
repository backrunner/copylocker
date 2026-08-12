import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'CopyLocker Web Lab — Next.js',
  description: 'CopyLocker @copylocker/web SDK demo with SSR',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
