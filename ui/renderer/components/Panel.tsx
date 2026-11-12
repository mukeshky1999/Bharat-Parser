import React from 'react';

/** A bordered surface. Panels are separated by borders, never by shadows. */
export const Panel: React.FC<React.HTMLAttributes<HTMLElement> & { as?: 'section' | 'div' }> = ({ as: Tag = 'section', className = '', children, ...rest }) => (
  <Tag className={`bg-slate-900 border border-slate-800 rounded-panel ${className}`} {...rest}>{children}</Tag>
);

export const PanelHeader: React.FC<{ title: string; count?: number | string; actions?: React.ReactNode; className?: string }> = ({ title, count, actions, className = '' }) => (
  <header className={`flex items-center gap-3 px-4 h-10 border-b border-slate-800 ${className}`}>
    <h2 className="text-[0.9375rem] font-semibold text-slate-50">{title}</h2>
    {count !== undefined && <span className="text-slate-400">{typeof count === 'number' ? count.toLocaleString() : count}</span>}
    {actions && <div className="ml-auto flex items-center gap-2">{actions}</div>}
  </header>
);
