import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Search, 
  Filter, 
  CheckCircle2, 
  Layers, 
  Tag, 
  Activity 
} from 'lucide-react';
import VulnerabilityCard from '../components/VulnerabilityCard';
import scanService from '../services/api';

export const Vulnerabilities = () => {
  const [vulns, setVulns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    loadVulnerabilities();
  }, [severityFilter, categoryFilter, statusFilter]);

  const loadVulnerabilities = async () => {
    setLoading(true);
    try {
      const filters = {};
      if (severityFilter !== 'ALL') filters.severity = severityFilter;
      if (categoryFilter !== 'ALL') filters.category = categoryFilter;
      if (statusFilter !== 'ALL') filters.status = statusFilter;
      if (searchTerm) filters.search = searchTerm;

      const data = await scanService.getVulnerabilities(filters);
      setVulns(data);
    } catch (err) {
      console.error('Failed to load vulnerabilities:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    loadVulnerabilities();
  };

  const handleStatusChange = async (vulnId, newStatus) => {
    try {
      await scanService.updateVulnerabilityStatus(vulnId, newStatus);
      setVulns(vulns.map((v) => (v.id === vulnId ? { ...v, remediation_status: newStatus } : v)));
    } catch (err) {
      console.error('Failed to update vulnerability status:', err);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-black text-white tracking-tight">Vulnerability Management</h1>
        <p className="mt-1 text-xs text-slate-400">
          Track, analyze, filter, and update remediation status across all detected vulnerabilities.
        </p>
      </div>

      {/* Filters & Search Control Bar */}
      <div className="rounded-2xl border border-slate-800 bg-[#0d1424] p-4 shadow-xl space-y-3">
        <form onSubmit={handleSearchSubmit} className="flex gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-3.5 top-3 h-4 w-4 text-slate-500" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search findings by title, description, or affected URL..."
              className="w-full rounded-xl border border-slate-700 bg-slate-900 pl-10 pr-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <button
            type="submit"
            className="px-5 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs transition"
          >
            Filter
          </button>
        </form>

        <div className="flex flex-wrap items-center gap-3 pt-2 border-t border-slate-800/80">
          {/* Severity Filter */}
          <div className="flex items-center gap-1.5 text-xs">
            <span className="text-slate-400 font-semibold">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          {/* Category Filter */}
          <div className="flex items-center gap-1.5 text-xs">
            <span className="text-slate-400 font-semibold">Category:</span>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Categories</option>
              <option value="Headers">Headers</option>
              <option value="SSL/TLS">SSL/TLS</option>
              <option value="Cookies">Cookies</option>
              <option value="Information Disclosure">Info Disclosure</option>
              <option value="DNS/Network">DNS & Network</option>
              <option value="Configuration">Configuration</option>
            </select>
          </div>

          {/* Status Filter */}
          <div className="flex items-center gap-1.5 text-xs">
            <span className="text-slate-400 font-semibold">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Statuses</option>
              <option value="Open">Open</option>
              <option value="In Progress">In Progress</option>
              <option value="Fixed">Fixed</option>
              <option value="Accepted Risk">Accepted Risk</option>
            </select>
          </div>

          <div className="ml-auto text-xs text-slate-400 font-mono">
            Total Results: <span className="font-bold text-cyan-400">{vulns.length}</span>
          </div>
        </div>
      </div>

      {/* Vulnerabilities List */}
      <div className="space-y-3">
        {loading ? (
          <div className="p-12 text-center text-xs text-slate-400">
            <div className="mx-auto h-6 w-6 animate-spin rounded-full border-2 border-cyan-400 border-t-transparent" />
            <p className="mt-2">Loading security inventory...</p>
          </div>
        ) : vulns.length === 0 ? (
          <div className="rounded-2xl border border-slate-800 bg-[#0d1424] p-12 text-center text-xs text-slate-400">
            No vulnerabilities matched the selected filters.
          </div>
        ) : (
          vulns.map((vuln, idx) => (
            <VulnerabilityCard
              key={vuln.id}
              vuln={vuln}
              index={idx + 1}
              onStatusChange={handleStatusChange}
            />
          ))
        )}
      </div>
    </div>
  );
};

export default Vulnerabilities;
