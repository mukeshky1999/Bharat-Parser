import React from 'react';
import type { LucideIcon } from 'lucide-react';
import type { Hue } from '../workspace/dataTree';

/* Shared building blocks. Token classes only: page, surface, sunken, hover, line, ink, muted, faint, accent, rec, ok, warn, g-*. */

const TILE: Record<Hue, string> = {
  accent: 'bg-accent-soft text-accent-ink',
  comm: 'bg-g-comm-soft text-g-comm',
  money: 'bg-g-money-soft text-g-money',
  places: 'bg-g-places-soft text-g-places',
  files: 'bg-g-files-soft text-g-files',
  analysis: 'bg-g-analysis-soft text-g-analysis',
  report: 'bg-g-report-soft text-g-report',
};

/** The coloured icon square that stands for a data group. The hue is used here and nowhere else. */
export const GroupTile: React.FC<{ hue: Hue; icon: LucideIcon; size?: 'sm' | 'md' | 'lg' }> = ({ hue, icon: Icon, size = 'md' }) => {
  const box = size === 'lg' ? 'w-11 h-11 rounded-xl' : size === 'sm' ? 'w-5 h-5 rounded-md' : 'w-[26px] h-[26px] rounded-[7px]';
  const ic = size === 'lg' ? 'w-5 h-5' : size === 'sm' ? 'w-3 h-3' : 'w-4 h-4';
  return (
    <span className={`${box} ${TILE[hue]} grid place-items-center shrink-0`} aria-hidden="true">
      <Icon className={ic} />
    </span>
  );
};

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'icon';
const BUTTON: Record<ButtonVariant, string> = {
  primary: 'bg-accent border border-accent text-on-accent hover:brightness-110 px-3',
  secondary: 'bg-surface border border-line-strong text-ink hover:bg-hover px-3',
  ghost: 'bg-transparent border border-transparent text-ink hover:bg-hover px-3',
  icon: 'bg-transparent border border-line-strong text-muted hover:bg-hover hover:text-ink w-8 justify-center',
};

export const Button = React.forwardRef<HTMLButtonElement, React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }>(
  ({ variant = 'secondary', className = '', type = 'button', ...rest }, ref) => (
    <button ref={ref} type={type} {...rest}
      className={`inline-flex items-center gap-2 h-8 rounded-lg font-medium whitespace-nowrap disabled:opacity-50 disabled:cursor-not-allowed ${BUTTON[variant]} ${className}`} />
  ),
);
Button.displayName = 'Button';

type ChipTone = 'rec' | 'ok' | 'warn' | 'in' | 'out' | 'neutral';
const CHIP: Record<ChipTone, string> = {
  rec: 'text-rec bg-rec-soft',
  ok: 'text-ok bg-ok-soft',
  warn: 'text-warn bg-warn-soft',
  in: 'text-g-money bg-g-money-soft',
  out: 'text-g-files bg-g-files-soft',
  neutral: 'text-muted bg-sunken',
};

export const Chip: React.FC<{ tone?: ChipTone; title?: string; children: React.ReactNode }> = ({ tone = 'neutral', title, children }) => (
  <span title={title} className={`inline-flex items-center gap-1 text-[0.6875rem] font-semibold px-[7px] py-px rounded-full whitespace-nowrap ${CHIP[tone]}`}>{children}</span>
);

/** "+N" marker for records that came from deleted or carved data. */
export const RecoveredChip: React.FC<{ n: number; label?: string }> = ({ n, label }) => (
  <Chip tone="rec" title={`${n.toLocaleString()} recovered (deleted) records`}>+{n.toLocaleString()}{label ? ` ${label}` : ''}</Chip>
);

export const CountChip: React.FC<{ n: number }> = ({ n }) => <span className="text-ink font-medium">{n.toLocaleString()}</span>;

export const Card: React.FC<{ title?: React.ReactNode; aside?: React.ReactNode; className?: string; bodyClassName?: string; children: React.ReactNode }> = ({
  title, aside, className = '', bodyClassName = 'px-4 py-3.5', children,
}) => (
  <section className={`card ${className}`}>
    {title && (
      <div className="flex items-center gap-2 px-4 py-3 border-b border-line">
        <h2 className="font-semibold">{title}</h2>
        {aside && <span className="ml-auto text-[0.75rem] font-normal text-muted">{aside}</span>}
      </div>
    )}
    <div className={bodyClassName}>{children}</div>
  </section>
);

export interface SegmentOption { value: string; label: string }

export const Segmented: React.FC<{ options: SegmentOption[]; value: string; onChange: (v: string) => void; label?: string }> = ({ options, value, onChange, label }) => (
  <div role="group" aria-label={label} className="inline-flex border border-line-strong rounded-lg overflow-hidden bg-surface">
    {options.map((o, i) => (
      <button key={o.value} type="button" aria-pressed={value === o.value} onClick={() => onChange(o.value)}
        className={`px-3 py-1 font-medium ${i > 0 ? 'border-l border-line' : ''} ${value === o.value ? 'bg-accent-soft text-accent-ink font-semibold' : 'text-muted hover:bg-hover'}`}>
        {o.label}
      </button>
    ))}
  </div>
);

export const Tabs: React.FC<{ tabs: SegmentOption[]; value: string; onChange: (v: string) => void; label?: string }> = ({ tabs, value, onChange, label }) => (
  <div role="tablist" aria-label={label} className="flex gap-0.5 border-b border-line px-3">
    {tabs.map((t) => (
      <button key={t.value} type="button" role="tab" aria-selected={value === t.value} onClick={() => onChange(t.value)}
        className={`px-2.5 py-2 -mb-px border-b-2 ${value === t.value ? 'text-ink border-accent font-semibold' : 'text-muted border-transparent font-medium hover:text-ink'}`}>
        {t.label}
      </button>
    ))}
  </div>
);

/** Title row of a list view: name, count, recovered count, an optional segmented filter, search and actions. */
export const ViewHeader: React.FC<{
  title: string;
  count?: number;
  recovered?: number;
  segment?: { value: string; onChange: (v: string) => void; options?: SegmentOption[] };
  search?: React.ReactNode;
  actions?: React.ReactNode;
}> = ({ title, count, recovered, segment, search, actions }) => (
  <div className="flex items-center gap-3 flex-wrap mb-3.5">
    <h2 className="text-lg font-semibold tracking-tight">{title}</h2>
    {count !== undefined && <span className="text-muted">{count.toLocaleString()} record{count === 1 ? '' : 's'}</span>}
    {recovered !== undefined && recovered > 0 && <RecoveredChip n={recovered} label="recovered" />}
    {segment && (
      <Segmented value={segment.value} onChange={segment.onChange}
        options={segment.options ?? [{ value: 'all', label: 'All' }, { value: 'recovered', label: 'Recovered' }]} />
    )}
    <span className="flex-1" />
    {search}
    {actions}
  </div>
);

export const EmptyState: React.FC<{ icon?: LucideIcon; hue?: Hue; title: string; children?: React.ReactNode }> = ({ icon, hue = 'accent', title, children }) => (
  <div className="grid place-items-center text-center gap-2.5 px-5 py-16">
    {icon && <GroupTile hue={hue} icon={icon} size="lg" />}
    <h2 className="text-base font-semibold">{title}</h2>
    {children && <p className="text-muted max-w-[46ch]">{children}</p>}
  </div>
);

export const KeyValue: React.FC<{ items: Array<[React.ReactNode, React.ReactNode]>; className?: string }> = ({ items, className = '' }) => (
  <dl className={`grid grid-cols-[max-content_minmax(0,1fr)] gap-x-[18px] gap-y-[7px] m-0 ${className}`}>
    {items.map(([k, v], i) => (
      <React.Fragment key={i}>
        <dt className="text-muted">{k}</dt>
        <dd className="m-0 break-words">{v}</dd>
      </React.Fragment>
    ))}
  </dl>
);

/** A clickable count card: group tile, name, a big number, and a line of chips under it. */
export const StatTile: React.FC<{
  hue: Hue; icon: LucideIcon; label: string; value: React.ReactNode; sub?: React.ReactNode; onClick?: () => void;
}> = ({ hue, icon, label, value, sub, onClick }) => {
  const body = (
    <>
      <span className="flex items-center gap-2.5"><GroupTile hue={hue} icon={icon} /><span className="font-semibold">{label}</span></span>
      <span className="text-2xl font-bold tracking-tight leading-none">{value}</span>
      <span className="flex gap-2 items-center text-[0.75rem] text-muted min-h-[18px]">{sub}</span>
    </>
  );
  const cls = 'text-left flex flex-col gap-2.5 p-3.5 border border-line rounded-[10px] bg-surface shadow-card';
  return onClick
    ? <button type="button" onClick={onClick} className={`${cls} hover:border-line-strong hover:bg-hover`}>{body}</button>
    : <div className={cls}>{body}</div>;
};
