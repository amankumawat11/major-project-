import React, { useState } from 'react';
import { 
  Globe, 
  Search, 
  Shield, 
  CheckCircle2, 
  Clock, 
  AlertTriangle, 
  Download, 
  Sparkles, 
  MessageSquare,
  ShieldCheck,
  FileText,
  Code2,
  ExternalLink,
  Info
} from 'lucide-react';
import ScoreGauge from '../components/ScoreGauge';
import VulnerabilityCard from '../components/VulnerabilityCard';
import ScanProgress from '../components/ScanProgress';
import scanService from '../services/api';

export const Scanner = ({ onNavigateToAssistant }) => {
  const [targetInput, setTargetInput] = useState('');
  const [scanMode, setScanMode] = useState('quick');
  const [authorized, setAuthorized] = useState(true);
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('findings'); // 'findings' | 'recommendations' | 'raw'

  const handleStartScan = async (e) => {
    e.preventDefault();
    if (!targetInput.trim()) return;

    if (!authorized) {
      setError('You must confirm authorization to scan this domain.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const result = await scanService.performScan(targetInput.trim(), scanMode, authorized);
      setScanResult(result);
    } catch (err) {
      console.error('Scan failed:', err);
      const msg = err.response?.data?.detail || err.message || 'Failed to complete security scan.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleStatusChange = async (vulnId, newStatus) => {
    try {
      await scanService.updateVulnerabilityStatus(vulnId, newStatus);
      // Update local state
      if (scanResult) {
        setScanResult({
          ...scanResult,
          vulnerabilities: scanResult.vulnerabilities.map((v) =>
            v.id === vulnId ? { ...v, remediation_status: newStatus } : v
          ),
        });
      }
    } catch (err) {
      console.error('Failed to update status:', err);
    }
  };

  // Severity counts
  const vulns = scanResult?.vulnerabilities || [];
  const highCount = vulns.filter((v) => v.severity === 'HIGH' || v.severity === 'CRITICAL').length;
  const medCount = vulns.filter((v) => v.severity === 'MEDIUM').length;
  const lowCount = vulns.filter((v) => v.severity === 'LOW' || v.severity === 'INFORMATIONAL').length;

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Title Header Matching Visual Reference */}
      <div>
        <div className="flex items-center gap-2">
          <h1 className="text-2xl font-black text-white tracking-tight">SecureExplain AI</h1>
          <span className="text-xs font-bold px-2 py-0.5 rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
            Beta
          </span>
        </div>
        <p className="mt-1 text-xs text-slate-400">
          Analyse a website's security, get clear AI explanations, and actionable fixes.
        </p>
      </div>

      {/* Target Input Search Bar - Matching Screenshot */}
      <form onSubmit={handleStartScan} className="space-y-3">
        <div className="relative flex flex-col sm:flex-row items-stretch sm:items-center rounded-2xl border border-slate-700/80 bg-[#0c1322] p-1.5 shadow-2xl focus-within:border-cyan-500/60 transition-all">
          <div className="flex items-center flex-1 px-3">
            <Globe className="h-5 w-5 text-slate-400 shrink-0" />
            <input
              type="text"
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              placeholder="https://example.com or domain.com"
              className="w-full bg-transparent px-3 py-2.5 text-sm font-medium text-white placeholder-slate-500 focus:outline-none"
              disabled={loading}
              required
            />
          </div>

          <div className="flex items-center gap-2 px-2 py-1 sm:py-0">
            {/* Scan Mode Selector */}
            <select
              value={scanMode}
              onChange={(e) => setScanMode(e.target.value)}
              disabled={loading}
              className="bg-slate-800/80 border border-slate-700 text-xs font-semibold rounded-xl px-3 py-2.5 text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="quick">Quick Scan</option>
              <option value="full">Full Scan</option>
              <option value="passive">Passive Audit</option>
            </select>

            {/* Scan Website Gradient Button */}
            <button
              type="submit"
              disabled={loading}
              className="cyber-button-gradient flex items-center justify-center gap-2 px-6 py-2.5 rounded-xl text-xs font-bold text-white shadow-lg shadow-indigo-500/25 disabled:opacity-50 transition"
            >
              <Search className="h-4 w-4" />
              <span>{loading ? 'Scanning...' : 'Scan Website'}</span>
            </button>
          </div>
        </div>

        {/* Authorization checkbox & safety notice */}
        <div className="flex items-center justify-between px-2 text-xs">
          <label className="flex items-center gap-2 text-slate-400 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={authorized}
              onChange={(e) => setAuthorized(e.target.checked)}
              className="rounded border-slate-700 bg-slate-800 text-cyan-500 focus:ring-0 focus:ring-offset-0"
            />
            <span>I confirm that I own or have explicit authorization to assess this website.</span>
          </label>
          <span className="text-[11px] text-slate-500 hidden md:inline">
            Non-intrusive safe checks &bull; SSRF Protected
          </span>
        </div>
      </form>

      {/* Error Banner */}
      {error && (
        <div className="flex items-start gap-3 rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-xs text-red-300">
          <AlertTriangle className="h-5 w-5 shrink-0 text-red-400" />
          <div>
            <span className="font-bold">Scan Execution Blocked or Failed:</span>
            <p className="mt-0.5 text-slate-300">{error}</p>
          </div>
        </div>
      )}

      {/* Loading Progress State */}
      {loading && (
        <ScanProgress target={targetInput} scanMode={scanMode} />
      )}

      {/* Scan Results Panel - Matching Visual Reference */}
      {scanResult && !loading && (
        <div className="space-y-6">
          {/* Result Card Container */}
          <div className="rounded-2xl border border-slate-800/80 bg-[#0d1424]/90 p-6 shadow-2xl backdrop-blur-md">
            {/* Top Status Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
              <div className="flex items-center gap-2.5">
                <CheckCircle2 className="h-5 w-5 text-emerald-400 shrink-0" />
                <div>
                  <h3 className="text-base font-bold text-white font-mono">
                    {scanResult.target_url}
                  </h3>
                  <p className="text-xs text-emerald-400 font-medium">
                    Scan completed &bull; {scanResult.total_checks} checks performed
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-4 text-xs text-slate-400">
                <div className="flex items-center gap-1.5 font-mono">
                  <Clock className="h-3.5 w-3.5 text-slate-500" />
                  <span>Scan Time: {scanResult.scan_duration_seconds}s</span>
                </div>
                {/* PDF Report Download Button */}
                <a
                  href={scanService.getReportDownloadUrl(scanResult.scan_id)}
                  download
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition"
                >
                  <Download className="h-3.5 w-3.5 text-cyan-400" />
                  <span>Download Report</span>
                </a>
              </div>
            </div>

            {/* 3 Summary Cards Row - Exactly like Screenshot */}
            <div className="grid grid-cols-1 md:grid-cols-12 gap-4 mt-5">
              {/* 1. Security Score */}
              <div className="md:col-span-3 rounded-xl border border-slate-800 bg-[#0a0f1d] p-4 flex flex-col items-center justify-center">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-1">
                  Security Score
                </span>
                <ScoreGauge score={scanResult.security_score} riskLevel={scanResult.risk_level} />
              </div>

              {/* 2. Findings Summary */}
              <div className="md:col-span-4 rounded-xl border border-slate-800 bg-[#0a0f1d] p-4 flex flex-col justify-between">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">
                  Findings Summary
                </span>
                <div className="space-y-2.5">
                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2 text-slate-300">
                      <span className="h-2.5 w-2.5 rounded-full bg-red-500" />
                      <span>High Risk</span>
                    </div>
                    <span className="font-bold text-red-400 font-mono text-sm">{highCount}</span>
                  </div>

                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2 text-slate-300">
                      <span className="h-2.5 w-2.5 rounded-full bg-amber-500" />
                      <span>Medium Risk</span>
                    </div>
                    <span className="font-bold text-amber-400 font-mono text-sm">{medCount}</span>
                  </div>

                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2 text-slate-300">
                      <span className="h-2.5 w-2.5 rounded-full bg-blue-500" />
                      <span>Low Risk</span>
                    </div>
                    <span className="font-bold text-blue-400 font-mono text-sm">{lowCount}</span>
                  </div>
                </div>
              </div>

              {/* 3. AI Overall Assessment */}
              <div className="md:col-span-5 rounded-xl border border-indigo-500/20 bg-indigo-950/20 p-4 flex flex-col justify-between">
                <div>
                  <div className="flex items-center gap-1.5 text-indigo-300 text-xs font-bold uppercase tracking-wider mb-2">
                    <Sparkles className="h-4 w-4 text-indigo-400" />
                    <span>AI Overall Assessment</span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    {scanResult.overall_ai_assessment ||
                      'The website exhibits standard protections, but essential defense-in-depth headers and configurations are recommended.'}
                  </p>
                </div>
                <div className="mt-3 pt-2 border-t border-indigo-500/20 flex justify-end">
                  <button
                    onClick={() => onNavigateToAssistant && onNavigateToAssistant(scanResult.scan_id)}
                    className="flex items-center gap-1.5 text-xs text-indigo-400 hover:text-indigo-300 font-semibold"
                  >
                    <MessageSquare className="h-3.5 w-3.5" />
                    <span>Ask AI Assistant about these results &rarr;</span>
                  </button>
                </div>
              </div>
            </div>

            {/* Results Navigation Tabs - Matching Screenshot */}
            <div className="mt-8 border-b border-slate-800 flex items-center gap-2">
              <button
                onClick={() => setActiveTab('findings')}
                className={`flex items-center gap-2 px-4 py-2.5 text-xs font-bold tracking-wide border-b-2 transition ${
                  activeTab === 'findings'
                    ? 'border-cyan-400 text-cyan-300'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <ShieldCheck className="h-4 w-4" />
                <span>Detailed Findings</span>
                <span className="ml-1 text-[10px] px-1.5 py-0.2 rounded-full bg-slate-800 text-slate-300">
                  {vulns.length}
                </span>
              </button>

              <button
                onClick={() => setActiveTab('recommendations')}
                className={`flex items-center gap-2 px-4 py-2.5 text-xs font-bold tracking-wide border-b-2 transition ${
                  activeTab === 'recommendations'
                    ? 'border-cyan-400 text-cyan-300'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <Sparkles className="h-4 w-4" />
                <span>AI Recommendations</span>
              </button>

              <button
                onClick={() => setActiveTab('raw')}
                className={`flex items-center gap-2 px-4 py-2.5 text-xs font-bold tracking-wide border-b-2 transition ${
                  activeTab === 'raw'
                    ? 'border-cyan-400 text-cyan-300'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <Code2 className="h-4 w-4" />
                <span>Raw Results</span>
              </button>
            </div>

            {/* Tab 1: Detailed Findings (Matching Table in Visual Reference) */}
            {activeTab === 'findings' && (
              <div className="mt-4 space-y-3">
                <div className="hidden md:flex items-center justify-between px-4 py-2 text-[11px] font-bold uppercase tracking-wider text-slate-500">
                  <span className="flex-1">Finding</span>
                  <div className="flex items-center gap-8 w-60 justify-end">
                    <span>Severity</span>
                    <span>Remediation Status</span>
                    <span className="w-8"></span>
                  </div>
                </div>

                {vulns.length === 0 ? (
                  <div className="text-center py-10 text-slate-400 text-xs">
                    No security vulnerabilities detected. Your target has passed all active checks!
                  </div>
                ) : (
                  vulns.map((vuln, idx) => (
                    <VulnerabilityCard
                      key={vuln.id || idx}
                      vuln={vuln}
                      index={idx + 1}
                      onStatusChange={handleStatusChange}
                    />
                  ))
                )}
              </div>
            )}

            {/* Tab 2: AI Recommendations Checklist */}
            {activeTab === 'recommendations' && (
              <div className="mt-6 space-y-4">
                <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
                  <h4 className="text-sm font-bold text-white flex items-center gap-2">
                    <Sparkles className="h-4 w-4 text-cyan-400" />
                    <span>Prioritized Remediation Checklist</span>
                  </h4>
                  <p className="mt-1 text-xs text-slate-400">
                    Fix high severity findings first to make the biggest leap in your security score.
                  </p>

                  <div className="mt-4 space-y-3">
                    {vulns.map((v, i) => (
                      <div
                        key={v.id || i}
                        className="flex items-start gap-3 p-3 rounded-lg border border-slate-800/80 bg-slate-950/40"
                      >
                        <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-cyan-500/10 text-[10px] font-bold text-cyan-400 border border-cyan-500/30">
                          {i + 1}
                        </span>
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-bold text-white">{v.title}</span>
                            <span className="text-[10px] font-semibold text-slate-400 uppercase">
                              ({v.severity})
                            </span>
                          </div>
                          <p className="mt-1 text-xs text-slate-300">
                            {v.ai_developer_action || v.remediation_recommendation}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Tab 3: Raw Results JSON */}
            {activeTab === 'raw' && (
              <div className="mt-6">
                <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs text-cyan-300 font-mono overflow-x-auto max-h-96">
                  {JSON.stringify(scanResult, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default Scanner;
