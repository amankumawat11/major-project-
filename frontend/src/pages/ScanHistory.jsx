import React, { useState, useEffect } from 'react';
import { 
  History, 
  Trash2, 
  GitCompare, 
  Download, 
  ExternalLink, 
  Search, 
  Globe, 
  AlertCircle,
  Clock,
  Eye,
  CheckCircle2
} from 'lucide-react';
import RiskBadge from '../components/RiskBadge';
import CompareModal from '../components/CompareModal';
import scanService from '../services/api';

export const ScanHistory = ({ onOpenScanDetail }) => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [isCompareOpen, setIsCompareOpen] = useState(false);
  const [compareResult, setCompareResult] = useState(null);
  const [comparing, setComparing] = useState(false);

  useEffect(() => {
    loadScans();
  }, []);

  const loadScans = async () => {
    setLoading(true);
    try {
      const data = await scanService.getScans();
      setScans(data);
    } catch (err) {
      console.error('Failed to load scan history:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (scanId) => {
    if (!window.confirm('Are you sure you want to delete this scan record and its findings?')) {
      return;
    }
    try {
      await scanService.deleteScan(scanId);
      setScans(scans.filter((s) => s.scan_id !== scanId));
    } catch (err) {
      console.error('Failed to delete scan:', err);
    }
  };

  const handleCompare = async (id1, id2) => {
    setComparing(true);
    try {
      const res = await scanService.compareScans(id1, id2);
      setCompareResult(res);
    } catch (err) {
      console.error('Comparison error:', err);
      alert('Failed to compare scans: ' + (err.response?.data?.detail || err.message));
    } finally {
      setComparing(false);
    }
  };

  const filteredScans = scans.filter((s) =>
    s.target_domain.toLowerCase().includes(searchTerm.toLowerCase()) ||
    s.target_url.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-black text-white tracking-tight">Scan History & Audit Logs</h1>
          <p className="mt-1 text-xs text-slate-400">
            Persistent records of all website security evaluations and generated PDF reports.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              setCompareResult(null);
              setIsCompareOpen(true);
            }}
            disabled={scans.length < 2}
            className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 transition disabled:opacity-40"
          >
            <GitCompare className="h-4 w-4 text-cyan-400" />
            <span>Compare Two Scans</span>
          </button>
        </div>
      </div>

      {/* Search Input */}
      <div className="relative max-w-md">
        <Search className="absolute left-3.5 top-3 h-4 w-4 text-slate-500" />
        <input
          type="text"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Filter scans by domain name..."
          className="w-full rounded-xl border border-slate-800 bg-[#0d1424] pl-10 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
        />
      </div>

      {/* History Table */}
      <div className="rounded-2xl border border-slate-800 bg-[#0d1424] overflow-hidden shadow-xl">
        {loading ? (
          <div className="p-12 text-center text-xs text-slate-400">
            <div className="mx-auto h-6 w-6 animate-spin rounded-full border-2 border-cyan-400 border-t-transparent" />
            <p className="mt-2">Loading historical audits...</p>
          </div>
        ) : filteredScans.length === 0 ? (
          <div className="p-12 text-center text-xs text-slate-400">
            No scans match your criteria. Start scanning to populate this history!
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="border-b border-slate-800 bg-slate-900/60 text-[11px] font-bold uppercase tracking-wider text-slate-400">
                <tr>
                  <th className="py-3 px-4">Target Website</th>
                  <th className="py-3 px-4">Mode</th>
                  <th className="py-3 px-4">Security Score</th>
                  <th className="py-3 px-4">Risk Level</th>
                  <th className="py-3 px-4">Findings</th>
                  <th className="py-3 px-4">Scan Date</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredScans.map((scan) => (
                  <tr key={scan.scan_id} className="hover:bg-slate-800/30 transition">
                    <td className="py-3.5 px-4 font-mono font-medium text-white flex items-center gap-2">
                      <Globe className="h-4 w-4 text-cyan-400 shrink-0" />
                      <div>
                        <div>{scan.target_domain}</div>
                        <div className="text-[10px] text-slate-500 font-sans">{scan.target_ip || 'IP Resolved'}</div>
                      </div>
                    </td>
                    <td className="py-3.5 px-4 capitalize text-slate-400">{scan.scan_mode}</td>
                    <td className="py-3.5 px-4">
                      <span className={`font-mono font-bold text-sm ${
                        scan.security_score >= 80 ? 'text-emerald-400' :
                        scan.security_score >= 60 ? 'text-amber-400' : 'text-red-400'
                      }`}>
                        {scan.security_score}/100
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <RiskBadge severity={scan.risk_level} size="sm" />
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="font-mono">{scan.total_vulnerabilities} issues</span>
                      {scan.critical_count > 0 && (
                        <span className="ml-1.5 text-[10px] text-red-400 font-bold">
                          ({scan.critical_count} Crit)
                        </span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 font-mono text-[11px]">
                      {new Date(scan.created_at).toLocaleString()}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        {/* Open Scan Details in Scanner */}
                        <button
                          onClick={() => onOpenScanDetail && onOpenScanDetail(scan.scan_id)}
                          title="View Scan Details"
                          className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-cyan-300 transition"
                        >
                          <Eye className="h-4 w-4" />
                        </button>

                        {/* Download PDF Report */}
                        <a
                          href={scanService.getReportDownloadUrl(scan.scan_id)}
                          download
                          title="Download PDF Audit Report"
                          className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-emerald-300 transition"
                        >
                          <Download className="h-4 w-4" />
                        </a>

                        {/* Delete Scan Record */}
                        <button
                          onClick={() => handleDelete(scan.scan_id)}
                          title="Delete Scan Record"
                          className="p-1.5 rounded-lg bg-slate-800 hover:bg-red-500/20 text-slate-400 hover:text-red-400 transition"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Compare Modal */}
      <CompareModal
        isOpen={isCompareOpen}
        onClose={() => setIsCompareOpen(false)}
        scans={scans}
        onCompare={handleCompare}
        compareResult={compareResult}
        loading={comparing}
      />
    </div>
  );
};

export default ScanHistory;
