import { useEffect, useId, useRef, type ReactNode } from 'react';
import { X } from 'lucide-react';
import { motion } from 'motion/react';

interface ModalShellProps {
  title: string;
  description?: string;
  icon: ReactNode;
  children: ReactNode;
  onClose: () => void;
  closeDisabled?: boolean;
  maxWidth?: 'md' | 'lg';
}

export function ModalShell({
  title,
  description,
  icon,
  children,
  onClose,
  closeDisabled = false,
  maxWidth = 'md',
}: ModalShellProps) {
  const titleId = useId();
  const descriptionId = useId();
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const previousFocus =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const panel = panelRef.current;
    const focusable = panel?.querySelector<HTMLElement>(
      'button:not(:disabled), input:not(:disabled), select:not(:disabled), [tabindex]:not([tabindex="-1"])',
    );
    focusable?.focus();
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !closeDisabled) {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== 'Tab' || panel === null) return;
      const items = [
        ...panel.querySelectorAll<HTMLElement>(
          'button:not(:disabled), input:not(:disabled), select:not(:disabled), [tabindex]:not([tabindex="-1"])',
        ),
      ];
      if (items.length === 0) return;
      const first = items[0];
      const last = items.at(-1);
      if (first === undefined || last === undefined) return;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      document.body.style.overflow = previousOverflow;
      previousFocus?.focus();
    };
  }, [closeDisabled, onClose]);

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 p-4"
    >
      <motion.div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description === undefined ? undefined : descriptionId}
        initial={{ opacity: 0, scale: 0.95, y: 8 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.95, y: 8 }}
        className={`relative max-h-[90vh] w-full overflow-y-auto rounded-2xl bg-white p-6 shadow-xl sm:p-8 ${
          maxWidth === 'lg' ? 'max-w-lg' : 'max-w-md'
        }`}
      >
        <button
          type="button"
          onClick={onClose}
          disabled={closeDisabled}
          className="absolute right-3 top-3 rounded-lg p-1.5 text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-600 disabled:cursor-not-allowed disabled:opacity-40"
          aria-label={`Close ${title}`}
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </button>
        <div className="mb-5 flex items-start gap-3 pr-8">
          <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl bg-indigo-100 text-indigo-600">
            {icon}
          </div>
          <div>
            <h2 id={titleId} className="text-xl font-bold tracking-tight text-slate-900">
              {title}
            </h2>
            {description !== undefined && (
              <p id={descriptionId} className="mt-1 text-sm leading-relaxed text-slate-500">
                {description}
              </p>
            )}
          </div>
        </div>
        {children}
      </motion.div>
    </motion.div>
  );
}
