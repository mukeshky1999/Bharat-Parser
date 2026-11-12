import React, { Component, ErrorInfo, ReactNode } from 'react';
import ReactDOM from 'react-dom/client';
import { AppShell } from './workspace/AppShell';
import './index.css';

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ForensicErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  public state: ErrorBoundaryState = {
    hasError: false,
    error: null,
    errorInfo: null,
  };

  public static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    console.error('[ForensicErrorBoundary] Uncaught render error:', error, errorInfo);
    this.setState({ errorInfo });
  }

  private handleReset = (): void => {
    try {
      localStorage.clear();
      sessionStorage.clear();
    } catch {
      // Ignore storage errors
    }
    this.setState({ hasError: false, error: null, errorInfo: null });
    window.location.reload();
  };

  public render(): ReactNode {
    if (this.state.hasError) {
      return (
        <div className="h-screen w-screen flex flex-col items-center justify-center bg-slate-900 text-slate-50 p-6 select-text">
          <div className="max-w-xl w-full bg-slate-800 border border-red-500/50 rounded shadow-2xl p-6">
            <div className="flex items-center space-x-3 border-b border-slate-700 pb-4 mb-4">
              <div className="w-9 h-9 rounded bg-red-600 flex items-center justify-center font-bold text-lg font-mono">
                !
              </div>
              <div>
                <h1 className="text-base font-bold text-red-400">
                  BharatAnalyzer Forensic Engine Diagnostic
                </h1>
                <p className="text-xs text-slate-400">
                  A UI component encountered an unexpected render state.
                </p>
              </div>
            </div>

            <div className="bg-slate-950 border border-slate-800 rounded p-3 mb-4 font-mono text-xs text-red-300 max-h-48 overflow-y-auto">
              <div className="font-bold mb-1">
                {this.state.error?.name}: {this.state.error?.message}
              </div>
              {this.state.errorInfo?.componentStack && (
                <pre className="text-[0.6875rem] text-slate-400 whitespace-pre-wrap">
                  {this.state.errorInfo.componentStack}
                </pre>
              )}
            </div>

            <div className="flex items-center justify-between">
              <span className="text-[0.6875rem] text-slate-400 font-mono">
                Port: 3000 | Backend: 127.0.0.1:8000
              </span>
              <div className="flex items-center space-x-2">
                <button
                  onClick={this.handleReset}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-600 text-slate-50 text-xs font-semibold rounded shadow transition-colors cursor-pointer"
                >
                  Reset View State & Reload
                </button>
              </div>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <ForensicErrorBoundary>
      <AppShell />
    </ForensicErrorBoundary>
  </React.StrictMode>
);
