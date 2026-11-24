import React, { useState } from 'react';
import { X, GitCompare, ArrowRight, ShieldCheck, AlertTriangle } from 'lucide-react';
import RiskBadge from './RiskBadge';

export const CompareModal = ({ isOpen, onClose, scans, onCompare, compareResult, loading }) => {
  const [scanId1, setScanId1] = useState('');
  const [scanId2, setScanId2] = useState('');

  if (!isOpen) return null;

  const handleSubmit = (e) => {
    e.preventDefault();
    if (scanId1 && scanId2) {
      onCompare(scanId1, scanId2);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="relative w-full max-w-3xl rounded-2xl border border-slate-800 bg-[#0d1424] p-6 shadow-2xl max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-2.5">
            <GitCompare className="h-5 w-5 text-cyan-400" />
            <h3 className="text-base font-bold text-white">Compare Security Scans</h3>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white">
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Selection Form */}
        <form onSubmit={handleSubmit} className="mt-5 grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5">
              Base Scan (Older)
            </label>
            <select
              value={scanId1}
              onChange={(e) => setScanId1(e.target.value)}
              required
              className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="">Select Baseline Scan...</option>
              {scans.map((s) => (
                <option key={s.scan_id} value={s.scan_id}>
                  {s.target_domain} ({new Date(s.created_at).toLocaleDateString()}) - Score: {s.security_score}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5">
              Target Scan (Newer / Re-scan)
            </label>
            <select
              value={scanId2}
              onChange={(e) => setScanId2(e.target.value)}
              required
              className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="">Select Comparison Scan...</option>
              {scans.map((s) => (
                <option key={s.scan_id} value={s.scan_id}>
                  {s.target_domain} ({new Date(s.created_at).toLocaleDateString()}) - Score: {s.security_score}
                </option>
              ))}
            </select>
          </div>

          <div className="sm:col-span-2">
            <button
              type="submit"
              disabled={loading || !scanId1 || !scanId2}
              className="w-full rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold py-2 text-xs transition disabled:opacity-50"
            >
              {loading ? 'Comparing Security Findings...' : 'Run Comparative Analysis'}
            </button>
          </div>
        </form>

        {/* Comparison Results */}
        {compareResult && (
          <div className="mt-6 border-t border-slate-800 pt-5 space-y-4">
            {/* Score delta */}
            <div className="grid grid-cols-3 gap-3 text-center">
              <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                <span className="text-xs text-slate-400">Baseline Score</span>
                <p className="text-xl font-bold text-white">{compareResult.scan_1.security_score}/100</p>
              </div>
              <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                <span className="text-xs text-slate-400">Score Change</span>
                <p className={`text-xl font-black ${
                  compareResult.score_difference > 0 ? 'text-emerald-400' :
                  compareResult.score_difference < 0 ? 'text-red-400' : 'text-slate-300'
                }`}>
                  {compareResult.score_difference > 0 ? `+${compareResult.score_difference}` : compareResult.score_difference}
                </p>
              </div>
              <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                <span className="text-xs text-slate-400">New Score</span>
                <p className="text-xl font-bold text-white">{compareResult.scan_2.security_score}/100</p>
              </div>
            </div>

            {/* Resolved Vulnerabilities */}
            <div>
              <h4 className="text-xs font-bold text-emerald-400 flex items-center gap-1.5 uppercase tracking-wider mb-2">
                <ShieldCheck className="h-4 w-4" />
                <span>Resolved Vulnerabilities ({compareResult.resolved_vulnerabilities.length})</span>
              </h4>
              {compareResult.resolved_vulnerabilities.length === 0 ? (
                <p className="text-xs text-slate-500">No vulnerabilities were resolved between these scans.</p>
              ) : (
                <div className="space-y-1.5">
                  {compareResult.resolved_vulnerabilities.map((v) => (
                    <div key={v.id} className="flex items-center justify-between p-2 rounded bg-emerald-500/10 border border-emerald-500/20 text-xs">
                      <span className="text-slate-200">{v.title}</span>
                      <RiskBadge severity={v.severity} size="sm" />
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Newly Introduced Vulnerabilities */}
            <div>
              <h4 className="text-xs font-bold text-red-400 flex items-center gap-1.5 uppercase tracking-wider mb-2">
                <AlertTriangle className="h-4 w-4" />
                <span>New Findings Introduced ({compareResult.new_vulnerabilities.length})</span>
              </h4>
              {compareResult.new_vulnerabilities.length === 0 ? (
                <p className="text-xs text-slate-500">No new vulnerabilities were introduced.</p>
              ) : (
                <div className="space-y-1.5">
                  {compareResult.new_vulnerabilities.map((v) => (
                    <div key={v.id} className="flex items-center justify-between p-2 rounded bg-red-500/10 border border-red-500/20 text-xs">
                      <span className="text-slate-200">{v.title}</span>
                      <RiskBadge severity={v.severity} size="sm" />
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default CompareModal;
