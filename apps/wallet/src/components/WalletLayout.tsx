import type { ReactNode } from 'react';
import { Database, LockKeyhole } from 'lucide-react';

import { nexusApiUrl } from '../lib/wallet-adapter';
import { Brand } from './Brand';

interface WalletLayoutProps {
  children: ReactNode;
}

export function WalletLayout({ children }: WalletLayoutProps) {
  return (
    <div className="flex min-h-screen flex-col bg-slate-50 text-slate-900">
      <header className="sticky top-0 z-30 border-b border-slate-200 bg-white/95 backdrop-blur-sm">
        <div className="mx-auto flex h-16 max-w-5xl items-center justify-between px-4 sm:px-6 lg:px-8">
          <Brand compact />
          <div className="flex items-center gap-2">
            <div className="hidden items-center gap-2 rounded-lg bg-slate-50 px-3 py-2 text-xs font-medium text-slate-600 sm:flex">
              <LockKeyhole className="h-4 w-4 text-indigo-600" aria-hidden="true" />
              Keys stay on this device
            </div>
            <div
              className="flex items-center gap-1.5 rounded-lg px-2 py-2 text-xs text-slate-500"
              title={`Registry: ${nexusApiUrl.origin}`}
            >
              <Database className="h-4 w-4" aria-hidden="true" />
              <span className="hidden md:inline">Registry</span>
              <span
                className="h-2 w-2 rounded-full bg-emerald-500"
                aria-label="Registry configured"
              />
            </div>
          </div>
        </div>
      </header>
      <main className="mx-auto w-full max-w-5xl flex-1 px-4 py-8 sm:px-6 sm:py-10 lg:px-8">
        {children}
      </main>
      <footer className="mt-auto border-t border-slate-200 bg-white py-6">
        <div className="mx-auto flex max-w-5xl flex-col items-center justify-between gap-3 px-4 text-center text-xs text-slate-500 sm:flex-row sm:px-6 sm:text-left lg:px-8">
          <span>ROwO Nexus · Self-certifying identities</span>
          <span>No account · No analytics · No third-party scripts</span>
        </div>
      </footer>
    </div>
  );
}
