import React from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';

/** Previous/next paging bar. `page` is 1-based. Renders nothing for a single page. */
export const Pager: React.FC<{ page: number; pages: number; onPage: (p: number) => void }> = ({ page, pages, onPage }) => {
  if (pages <= 1) return null;
  return (
    <div className="shrink-0 flex items-center justify-center gap-3 h-10 border-t border-slate-800 bg-slate-900 text-slate-300">
      <button onClick={() => onPage(Math.max(1, page - 1))} disabled={page === 1} className="p-1 rounded-ctl hover:bg-slate-800 disabled:opacity-40" aria-label="Previous page"><ChevronLeft className="w-4 h-4" /></button>
      <span>Page {page} of {pages}</span>
      <button onClick={() => onPage(Math.min(pages, page + 1))} disabled={page === pages} className="p-1 rounded-ctl hover:bg-slate-800 disabled:opacity-40" aria-label="Next page"><ChevronRight className="w-4 h-4" /></button>
    </div>
  );
};
