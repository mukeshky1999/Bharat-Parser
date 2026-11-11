import React from 'react';
import { MaliciousApkFinding } from '../../shared/forensic-types';
import { AlertTriangle, ShieldAlert, Bot, Globe, Lock, Terminal } from 'lucide-react';

interface MaliciousApkViewProps {
  findings: MaliciousApkFinding[];
  selectedApkPath?: string;
  onSelectApk: (finding: MaliciousApkFinding) => void;
}

export const MaliciousApkView: React.FC<MaliciousApkViewProps> = ({
  findings,
  selectedApkPath,
  onSelectApk,
}) => {
  return (
    <div className="flex-1 flex flex-col bg-slate-950 overflow-hidden select-text">
      {/* Header */}
      <div className="h-10 bg-slate-900 border-b border-slate-800 px-3 flex items-center justify-between text-xs shrink-0 select-none">
        <div className="flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 text-rose-400" />
          <span className="font-bold text-slate-200">
            Malicious Mule APK & SMS Forwarder Triage Findings
          </span>
        </div>
        <div className="text-[11px] text-rose-400 font-mono font-bold">
          {findings.length} High-Risk Threat(s) Detected
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {findings.map((apk) => {
          const isSelected = selectedApkPath === apk.apkVfsPath;
          const hexOffset = `0x${apk.provenance.byteOffset.toString(16).toUpperCase().padStart(8, '0')}`;

          return (
            <div
              key={apk.packageName}
              onClick={() => onSelectApk(apk)}
              className={`bg-slate-900 border rounded-lg p-4 cursor-pointer transition-all space-y-3 ${
                isSelected ? 'border-rose-500 ring-2 ring-rose-500/30' : 'border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between">
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="text-sm font-bold text-slate-100">{apk.appName || apk.packageName}</span>
                    <span className="text-[10px] bg-rose-950 text-rose-300 border border-rose-700/60 px-2 py-0.5 rounded font-mono font-bold">
                      {apk.riskScore} THREAT
                    </span>
                  </div>
                  <div className="text-xs text-slate-400 font-mono mt-0.5">
                    Package: {apk.packageName} | VFS: {apk.apkVfsPath}
                  </div>
                </div>

                <div className="text-right text-[11px] font-mono">
                  <div className="text-amber-400 font-bold">{hexOffset}</div>
                  <div className="text-slate-500 text-[10px]">classes.dex string offset</div>
                </div>
              </div>

              {/* SHA-256 */}
              <div className="bg-slate-950 border border-slate-800 rounded p-2 text-xs font-mono">
                <span className="text-slate-500">APK SHA-256: </span>
                <span className="text-slate-300 break-all">{apk.sha256}</span>
              </div>

              {/* Telegram Bot C2 Tokens */}
              {apk.extractedTelegramBotTokens.length > 0 && (
                <div className="space-y-1">
                  <div className="flex items-center space-x-1.5 text-xs font-bold text-rose-400">
                    <Bot className="w-3.5 h-3.5" />
                    <span>Hardcoded Telegram Bot C2 Tokens (classes.dex):</span>
                  </div>
                  <div className="space-y-1">
                    {apk.extractedTelegramBotTokens.map((token) => (
                      <div key={token} className="bg-rose-950/40 border border-rose-900/60 rounded px-2.5 py-1 text-xs font-mono text-rose-200">
                        {token}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Telegram Chat IDs */}
              {apk.extractedTelegramChatIds.length > 0 && (
                <div className="space-y-1">
                  <div className="text-xs font-bold text-slate-300">Exfiltration Chat IDs:</div>
                  <div className="flex flex-wrap gap-1.5 font-mono text-xs">
                    {apk.extractedTelegramChatIds.map((cid) => (
                      <span key={cid} className="bg-slate-950 border border-slate-700 text-amber-300 px-2 py-0.5 rounded">
                        chat_id: {cid}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* C2 URLs */}
              {apk.extractedC2Urls.length > 0 && (
                <div className="space-y-1">
                  <div className="flex items-center space-x-1.5 text-xs font-bold text-blue-400">
                    <Globe className="w-3.5 h-3.5" />
                    <span>Exfiltration C2 Server Endpoints:</span>
                  </div>
                  <div className="space-y-1 font-mono text-xs">
                    {apk.extractedC2Urls.map((url) => (
                      <div key={url} className="bg-slate-950 border border-slate-800 text-sky-300 px-2.5 py-1 rounded truncate">
                        {url}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Dangerous Permissions */}
              <div className="space-y-1">
                <div className="text-xs font-bold text-slate-300">Dangerous Android Permissions:</div>
                <div className="flex flex-wrap gap-1">
                  {apk.dangerousPermissions.map((perm) => (
                    <span
                      key={perm}
                      className="text-[10px] bg-slate-950 text-rose-300 border border-rose-900/50 px-2 py-0.5 rounded font-mono"
                    >
                      {perm.replace('android.permission.', '')}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
