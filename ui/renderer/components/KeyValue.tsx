import React from 'react';

export interface KeyValueItem { label: string; value: React.ReactNode; mono?: boolean; wide?: boolean }

/** Label and value pairs in a grid. A missing value is shown as "not recorded", never blank or defaulted. */
export const KeyValue: React.FC<{ items: KeyValueItem[]; columns?: 1 | 2 | 3 | 4 }> = ({ items, columns = 2 }) => {
  const cols = { 1: 'grid-cols-1', 2: 'sm:grid-cols-2', 3: 'sm:grid-cols-2 lg:grid-cols-3', 4: 'sm:grid-cols-2 lg:grid-cols-4' }[columns];
  return (
    <dl className={`grid gap-x-6 gap-y-3 ${cols}`}>
      {items.map((it) => (
        <div key={it.label} className={`min-w-0 ${it.wide ? 'sm:col-span-full' : ''}`}>
          <dt className="text-[0.75rem] text-slate-400">{it.label}</dt>
          <dd className={`mt-0.5 text-slate-100 break-words select-text ${it.mono ? 'font-mono text-[0.8125rem]' : ''}`}>
            {it.value === null || it.value === undefined || it.value === '' ? <span className="text-slate-500 italic">not recorded</span> : it.value}
          </dd>
        </div>
      ))}
    </dl>
  );
};
