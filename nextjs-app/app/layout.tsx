import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'mTLS Proxy Client',
  description: 'Next.js client for mTLS proxy server',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
