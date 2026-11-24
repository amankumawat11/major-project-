import React, { useState, useEffect } from 'react';
import { 
  Settings as SettingsIcon, 
  Key, 
  ShieldAlert, 
  Server, 
  Lock, 
  CheckCircle2, 
  AlertTriangle,
  Info
} from 'lucide-react';
import scanService from '../services/api';

export const Settings = () => {
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkBackend();
  }, []);

  const checkBackend = async () => {
    try {
      const data = await scanService.checkHealth();
      setHealth(data);
    } catch (err) {
      setHealth({ status: 'offline', error: err.message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-black text-white tracking-tight">System Configuration</h1>
        <p className="mt-1 text-xs text-slate-400">
          Environment settings, Gemini AI API parameters, target validation rules, and scanner safeguards.
        </p>
      </div>

      {/* Backend & AI Service Status */}
      <div className="rounded-2xl border border-slate-800 bg-[#0d1424] p-6 shadow-xl space-y-4">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <Server className="h-4 w-4 text-cyan-400" />
          <span>Backend & Engine Status</span>
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/60">
            <span className="text-xs text-slate-400">API Health</span>
            <div className="mt-1 flex items-center gap-2">
              <span className={`h-2.5 w-2.5 rounded-full ${health?.status === 'healthy' ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`} />
              <span className="text-sm font-bold text-white capitalize">{health?.status || 'Checking...'}</span>
            </div>
          </div>

          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/60">
            <span className="text-xs text-slate-400">Database Engine</span>
            <div className="mt-1 flex items-center gap-2 text-sm font-bold text-white">
              <CheckCircle2 className="h-4 w-4 text-emerald-400" />
              <span>SQLite Persistent</span>
            </div>
          </div>

          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/60">
            <span className="text-xs text-slate-400">GenAI Provider</span>
            <div className="mt-1 flex items-center gap-2 text-sm font-bold text-white">
              <CheckCircle2 className="h-4 w-4 text-cyan-400" />
              <span>Google Gemini 2.5</span>
            </div>
          </div>
        </div>
      </div>

      {/* Gemini AI Key Setup */}
      <div className="rounded-2xl border border-slate-800 bg-[#0d1424] p-6 shadow-xl space-y-4">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <Key className="h-4 w-4 text-indigo-400" />
          <span>Google Gemini API Configuration</span>
        </h3>
        <p className="text-xs text-slate-400 leading-relaxed">
          SecureExplain AI leverages Google Gemini to synthesize beginner-friendly vulnerability explanations and remediation snippets.
          Configure your API key in the backend environment file (<code className="text-cyan-300 font-mono">backend/.env</code>).
        </p>

        <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-slate-300">
          <span className="text-slate-500"># In backend/.env:</span>
          <br />
          <span className="text-cyan-400">GEMINI_API_KEY</span>=AIzaSy...your_gemini_api_key_here
        </div>

        <div className="flex items-center gap-2 text-xs text-slate-400">
          <Info className="h-4 w-4 text-indigo-400" />
          <span>
            If no API key is specified, the application seamlessly runs using our comprehensive pre-computed cybersecurity knowledge base!
          </span>
        </div>
      </div>

      {/* Target Safety & Ethical Disclaimer */}
      <div className="rounded-2xl border border-amber-500/20 bg-amber-500/5 p-6 shadow-xl space-y-3">
        <h3 className="text-sm font-bold text-amber-300 flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-amber-400" />
          <span>Safe Scanning & SSRF Safeguards</span>
        </h3>
        <p className="text-xs text-slate-300 leading-relaxed">
          The built-in vulnerability detection engine is strictly defensive and non-destructive:
        </p>
        <ul className="text-xs text-slate-400 space-y-1.5 list-disc list-inside">
          <li>Private and loopback IP addresses (127.0.0.1, 10.0.0.0/8, 192.168.0.0/16, etc.) are strictly blocked.</li>
          <li>Cloud metadata endpoints (169.254.169.254, metadata.google.internal) are rejected to prevent SSRF.</li>
          <li>DNS rebinding checks verify target resolution at scan execution time.</li>
          <li>Rate limiting is enforced at 20 scans per minute per client IP.</li>
          <li>No brute-force attacks, destructive payloads, or credential cracking are ever performed.</li>
        </ul>
      </div>
    </div>
  );
};

export default Settings;
