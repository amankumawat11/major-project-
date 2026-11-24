import React, { useState, useEffect } from 'react';
import { Shield, Check, Loader2, Globe, Lock, FileText, Server, Sparkles } from 'lucide-react';

const SCAN_STAGES = [
  { id: 1, label: 'Target Validation & SSRF Guard', icon: Globe },
  { id: 2, label: 'SSL/TLS Cryptographic Analysis', icon: Lock },
  { id: 3, label: 'HTTP Security Headers & Disclosure Audit', icon: FileText },
  { id: 4, label: 'Cookie Attributes & Session Flags', icon: Server },
  { id: 5, label: 'DNS & Email Authentication (SPF/DMARC)', icon: Shield },
  { id: 6, label: 'Gemini Generative AI Explanation Synthesis', icon: Sparkles },
];

export const ScanProgress = ({ target, scanMode }) => {
  const [currentStageIndex, setCurrentStageIndex] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentStageIndex((prev) => (prev < SCAN_STAGES.length - 1 ? prev + 1 : prev));
    }, 1200);

    return () => clearInterval(interval);
  }, []);

  const progressPercentage = Math.round(((currentStageIndex + 1) / SCAN_STAGES.length) * 100);

  return (
    <div className="my-6 rounded-2xl border border-cyan-500/30 bg-slate-900/80 p-6 shadow-2xl backdrop-blur-md">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="relative flex h-14 w-14 items-center justify-center rounded-2xl bg-cyan-500/10 border border-cyan-500/40">
            <Loader2 className="h-7 w-7 animate-spin text-cyan-400" />
            <Shield className="absolute h-4 w-4 text-cyan-200" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="inline-block h-2.5 w-2.5 rounded-full bg-cyan-400 animate-ping" />
              <h3 className="text-lg font-bold text-white">Security Scan in Progress</h3>
            </div>
            <p className="text-sm text-slate-400">
              Auditing <span className="text-cyan-300 font-mono font-medium">{target}</span> ({scanMode} mode)
            </p>
          </div>
        </div>

        <div className="flex flex-col items-end">
          <span className="text-2xl font-black text-cyan-400">{progressPercentage}%</span>
          <span className="text-xs text-slate-500">Live Stage Execution</span>
        </div>
      </div>

      {/* Progress Bar */}
      <div className="mt-6 h-2 w-full overflow-hidden rounded-full bg-slate-800">
        <div
          className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-500 transition-all duration-500 ease-out"
          style={{ width: `${progressPercentage}%` }}
        />
      </div>

      {/* Stage Indicators */}
      <div className="mt-6 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
        {SCAN_STAGES.map((stage, idx) => {
          const Icon = stage.icon;
          const isDone = idx < currentStageIndex;
          const isCurrent = idx === currentStageIndex;

          return (
            <div
              key={stage.id}
              className={`flex items-center gap-3 rounded-lg border p-2.5 transition-all ${
                isDone
                  ? 'border-emerald-500/30 bg-emerald-500/5 text-emerald-300'
                  : isCurrent
                  ? 'border-cyan-500/50 bg-cyan-500/10 text-cyan-200 shadow-sm'
                  : 'border-slate-800 bg-slate-900/40 text-slate-500'
              }`}
            >
              <div
                className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-xs font-bold ${
                  isDone
                    ? 'bg-emerald-500/20 text-emerald-400'
                    : isCurrent
                    ? 'bg-cyan-500/20 text-cyan-400 animate-pulse'
                    : 'bg-slate-800 text-slate-600'
                }`}
              >
                {isDone ? <Check className="h-3.5 w-3.5" /> : idx + 1}
              </div>
              <span className="text-xs font-medium truncate">{stage.label}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default ScanProgress;
