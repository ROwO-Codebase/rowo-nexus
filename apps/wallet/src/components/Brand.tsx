import { ShieldCheck } from 'lucide-react';

interface BrandProps {
  compact?: boolean;
}

export function Brand({ compact = false }: BrandProps) {
  return (
    <div className="flex min-w-0 items-center gap-2.5">
      <img
        src="/logo.png"
        alt=""
        width={compact ? 32 : 40}
        height={compact ? 32 : 40}
        className={compact ? 'h-8 w-8 rounded-xl' : 'h-10 w-10 rounded-2xl'}
      />
      <div className="min-w-0">
        <div className="truncate text-lg font-semibold tracking-tight text-slate-800">
          ROwO <span className="text-indigo-600">Nexus</span>
        </div>
        {!compact && (
          <div className="flex items-center gap-1 text-xs text-slate-500">
            <ShieldCheck className="h-3 w-3 text-indigo-500" aria-hidden="true" />
            Local identity wallet
          </div>
        )}
      </div>
    </div>
  );
}
