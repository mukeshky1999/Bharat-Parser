import React from 'react';

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger';
const VARIANT: Record<Variant, string> = {
  primary: 'bg-cyan-600 text-slate-50 hover:bg-cyan-500 border border-transparent',
  secondary: 'bg-transparent text-slate-200 border border-slate-700 hover:bg-slate-800',
  ghost: 'bg-transparent text-slate-300 border border-transparent hover:bg-slate-800',
  danger: 'bg-transparent text-rose-300 border border-rose-700 hover:bg-slate-800',
};

export const Button: React.FC<React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; size?: 'sm' | 'md' }> = ({ variant = 'secondary', size = 'md', className = '', type = 'button', ...rest }) => (
  <button
    type={type}
    className={`inline-flex items-center justify-center gap-2 rounded-ctl font-medium transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${size === 'sm' ? 'h-7 px-2.5' : 'h-8 px-3'} ${VARIANT[variant]} ${className}`}
    {...rest}
  />
);
