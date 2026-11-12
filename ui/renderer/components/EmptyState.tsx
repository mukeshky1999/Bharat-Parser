import React from 'react';

export const EmptyState: React.FC<{ title: string; children?: React.ReactNode }> = ({ title, children }) => (
  <div className="p-10 text-center">
    <p className="text-slate-200 font-medium">{title}</p>
    {children && <p className="mt-1 text-slate-400">{children}</p>}
  </div>
);
