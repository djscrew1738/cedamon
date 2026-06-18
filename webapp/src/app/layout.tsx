import type { Metadata, Viewport } from 'next'
import { Suspense } from 'react'
import '@/styles/index.css'
import { QueryProvider } from '@/providers/QueryProvider'
import { AuthProvider } from '@/providers/AuthProvider'
import { ProjectProvider } from '@/providers/ProjectProvider'
import { ToastProvider, AlertProvider } from '@/components/ui'
import { AppLayout } from '@/components/layout'
import { ThemeDbBridge } from '@/components/ThemeDbBridge'

export const metadata: Metadata = {
  title: 'RedAmon',
  description: 'Security reconnaissance and vulnerability assessment dashboard',
  icons: {
    icon: '/favicon.ico',
    apple: '/favicon.png',
  },
}

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  maximumScale: 1,
  userScalable: false,
  viewportFit: 'cover',
  themeColor: [
    { media: '(prefers-color-scheme: dark)', color: '#1a1a2e' },
    { media: '(prefers-color-scheme: light)', color: '#f0f2f5' },
  ],
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        {/* Prevent flash of wrong theme & set mobile browser chrome color */}
        <script
          dangerouslySetInnerHTML={{
            __html: `
              (function() {
                try {
                  var theme = localStorage.getItem('redamon-theme');
                  if (theme === 'dark' || theme === 'light') {
                    document.documentElement.setAttribute('data-theme', theme);
                  } else if (window.matchMedia('(prefers-color-scheme: light)').matches) {
                    document.documentElement.setAttribute('data-theme', 'light');
                  } else {
                    document.documentElement.setAttribute('data-theme', 'dark');
                  }
                  var bg = getComputedStyle(document.documentElement).getPropertyValue('--bg-secondary').trim();
                  if (bg) {
                    var meta = document.querySelector('meta[name="theme-color"]');
                    if (!meta) { meta = document.createElement('meta'); meta.setAttribute('name', 'theme-color'); document.head.appendChild(meta); }
                    meta.setAttribute('content', bg);
                  }
                } catch (e) {}
              })();
            `,
          }}
        />
        <meta name="theme-color" content="#1a1a2e" />
        {/* Apple PWA / standalone app support */}
        <meta name="apple-mobile-web-app-capable" content="yes" />
        <meta name="apple-mobile-web-app-title" content="RedAmon" />
        <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
        <meta name="mobile-web-app-capable" content="yes" />
        <link rel="apple-touch-icon" href="/favicon.png" />
      </head>
      <body>
        <QueryProvider>
          <Suspense fallback={null}>
            <AuthProvider>
              <ThemeDbBridge />
              <ProjectProvider>
                <ToastProvider>
                  <AlertProvider>
                    <AppLayout>{children}</AppLayout>
                  </AlertProvider>
                </ToastProvider>
              </ProjectProvider>
            </AuthProvider>
          </Suspense>
        </QueryProvider>
      </body>
    </html>
  )
}
