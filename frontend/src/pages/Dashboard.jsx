import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  AlertCircle, 
  CheckCircle, 
  Globe, 
  ArrowUpRight, 
  TrendingUp, 
  Activity,
  Layers,
  Search,
  ExternalLink
} from 'lucide-react';
import { 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip, 
  Legend, 
  AreaChart, 
  Area 
} from 'recharts';
import StatCard from '../components/StatCard';
import RiskBadge from '../components/RiskBadge';
import scanService from '../services/api';

export const Dashboard = ({ onNavigateToScanner, onNavigateToScanDetail }) => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    setLoading(true);
    try {
      const data = await scanService.getDashboardStats();
      setStats(data);
    } catch (err) {
      console.error('Failed to load dashboard statistics:', err);
      setError('Unable to connect to the backend API.');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex h-96 items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-cyan-400 border-t-transparent" />
          <p className="text-xs text-slate-400">Loading security analytics from database...</p>
        </div>
      </div>
    );
  }

  // Check if empty state
  const hasScans = stats && stats.total_scans > 0;

  // Chart data preparation
  const severityChartData = [
    { name: 'Critical', count: stats?.critical_risks || 0, color: '#ef4444' },
    { name: 'High', count: stats?.high_risks || 0, color: '#f97316' },
    { name: 'Medium', count: stats?.medium_risks || 0, color: '#eab308' },
    { name: 'Low', count: stats?.low_risks || 0, color: '#10b981' },
  ].filter((item) => item.count > 0);

  const categoryChartData = Object.entries(stats?.category_distribution || {}).map(([key, val]) => ({
    category: key,
    vulnerabilities: val,
  }));

  const activityData = (stats?.recent_scans || []).slice().reverse().map((s, idx) => ({
    name: s.target_domain,
    score: s.security_score,
    vulnerabilities: s.total_vulnerabilities,
  }));

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Welcome Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-black text-white tracking-tight">Security Posture Dashboard</h1>
          <p className="mt-1 text-xs text-slate-400">
            Real-time vulnerability metrics, risk posture, and historical audit trends.
          </p>
        </div>
        <button
          onClick={onNavigateToScanner}
          className="cyber-button-gradient flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-bold text-white shadow-lg shadow-indigo-600/20 self-start sm:self-auto"
        >
          <Search className="h-4 w-4" />
          <span>Launch New Scan</span>
        </button>
      </div>

      {/* Overview Stat Cards Grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3.5">
        <StatCard
          title="Total Scans"
          value={stats?.total_scans || 0}
          icon={Activity}
          color="cyan"
          subtitle="Audited Targets"
        />
        <StatCard
          title="Vulnerabilities"
          value={stats?.total_vulnerabilities || 0}
          icon={ShieldAlert}
          color="blue"
          subtitle="Total Detected"
        />
        <StatCard
          title="Critical Risks"
          value={stats?.critical_risks || 0}
          icon={ShieldAlert}
          color="red"
          subtitle="Immediate Fix"
        />
        <StatCard
          title="High Risks"
          value={stats?.high_risks || 0}
          icon={AlertTriangle}
          color="orange"
          subtitle="Severe Exposure"
        />
        <StatCard
          title="Medium Risks"
          value={stats?.medium_risks || 0}
          icon={AlertCircle}
          color="amber"
          subtitle="Configuration Gap"
        />
        <StatCard
          title="Low Risks"
          value={stats?.low_risks || 0}
          icon={CheckCircle}
          color="emerald"
          subtitle="Minor Hardening"
        />
      </div>

      {/* Meaningful Empty State if no scans have been performed */}
      {!hasScans ? (
        <div className="rounded-2xl border border-slate-800 bg-[#0d1424] p-12 text-center shadow-xl">
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Globe className="h-8 w-8" />
          </div>
          <h3 className="mt-4 text-lg font-bold text-white">No Security Scans Recorded Yet</h3>
          <p className="mt-2 text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
            Scan your first domain or website to generate automated security scores, detect missing HTTP headers, 
            inspect SSL certificates, and receive Gemini Generative AI explanations.
          </p>
          <button
            onClick={onNavigateToScanner}
            className="mt-6 cyber-button-gradient inline-flex items-center gap-2 px-6 py-2.5 rounded-xl text-xs font-bold text-white"
          >
            <span>Scan Your First Website</span>
            <ArrowUpRight className="h-4 w-4" />
          </button>
        </div>
      ) : (
        <>
          {/* Charts Row */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            {/* 1. Vulnerability Severity Donut */}
            <div className="lg:col-span-4 rounded-2xl border border-slate-800 bg-[#0d1424] p-5 shadow-xl">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-red-400" />
                <span>Severity Distribution</span>
              </h3>
              <p className="mt-1 text-[11px] text-slate-500">Breakdown by threat level</p>

              <div className="h-56 mt-2">
                {severityChartData.length === 0 ? (
                  <div className="h-full flex items-center justify-center text-xs text-slate-500">
                    No vulnerabilities recorded!
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={severityChartData}
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={75}
                        paddingAngle={4}
                        dataKey="count"
                      >
                        {severityChartData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{ backgroundColor: '#090e1a', borderColor: '#1e293b', borderRadius: '8px', fontSize: '12px' }}
                      />
                      <Legend
                        verticalAlign="bottom"
                        wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                )}
              </div>
            </div>

            {/* 2. Category Breakdown Bar Chart */}
            <div className="lg:col-span-4 rounded-2xl border border-slate-800 bg-[#0d1424] p-5 shadow-xl">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <Layers className="h-4 w-4 text-cyan-400" />
                <span>Findings by Category</span>
              </h3>
              <p className="mt-1 text-[11px] text-slate-500">Web security vector breakdown</p>

              <div className="h-56 mt-2">
                {categoryChartData.length === 0 ? (
                  <div className="h-full flex items-center justify-center text-xs text-slate-500">
                    No category data available
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={categoryChartData}>
                      <XAxis dataKey="category" stroke="#64748b" fontSize={10} />
                      <YAxis stroke="#64748b" fontSize={10} />
                      <Tooltip
                        contentStyle={{ backgroundColor: '#090e1a', borderColor: '#1e293b', borderRadius: '8px', fontSize: '12px' }}
                      />
                      <Bar dataKey="vulnerabilities" fill="#0284c7" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </div>
            </div>

            {/* 3. Security Score Trends Area Chart */}
            <div className="lg:col-span-4 rounded-2xl border border-slate-800 bg-[#0d1424] p-5 shadow-xl">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <TrendingUp className="h-4 w-4 text-emerald-400" />
                <span>Security Score Trends</span>
              </h3>
              <p className="mt-1 text-[11px] text-slate-500">Score per evaluated target</p>

              <div className="h-56 mt-2">
                {activityData.length === 0 ? (
                  <div className="h-full flex items-center justify-center text-xs text-slate-500">
                    Need more scan records for trends
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={activityData}>
                      <defs>
                        <linearGradient id="scoreColor" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#00f0ff" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#00f0ff" stopOpacity={0.0} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="name" stroke="#64748b" fontSize={10} />
                      <YAxis domain={[0, 100]} stroke="#64748b" fontSize={10} />
                      <Tooltip
                        contentStyle={{ backgroundColor: '#090e1a', borderColor: '#1e293b', borderRadius: '8px', fontSize: '12px' }}
                      />
                      <Area
                        type="monotone"
                        dataKey="score"
                        stroke="#00f0ff"
                        strokeWidth={2}
                        fillOpacity={1}
                        fill="url(#scoreColor)"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                )}
              </div>
            </div>
          </div>

          {/* Recent Scans Table */}
          <div className="rounded-2xl border border-slate-800 bg-[#0d1424] p-6 shadow-xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <h3 className="text-sm font-bold text-white tracking-wide">Recent Security Scans</h3>
                <p className="text-xs text-slate-400">Latest website audits and automated evaluations</p>
              </div>
              <button
                onClick={onNavigateToScanner}
                className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1"
              >
                <span>Run New Scan</span>
                <ArrowUpRight className="h-3.5 w-3.5" />
              </button>
            </div>

            <div className="mt-4 overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="border-b border-slate-800 text-[11px] font-bold uppercase tracking-wider text-slate-500">
                  <tr>
                    <th className="pb-3">Domain</th>
                    <th className="pb-3">Scan Mode</th>
                    <th className="pb-3">Score</th>
                    <th className="pb-3">Risk Level</th>
                    <th className="pb-3">Findings</th>
                    <th className="pb-3">Date</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {(stats?.recent_scans || []).map((scan) => (
                    <tr
                      key={scan.scan_id}
                      onClick={() => onNavigateToScanDetail && onNavigateToScanDetail(scan.scan_id)}
                      className="cursor-pointer hover:bg-slate-800/40 transition"
                    >
                      <td className="py-3 font-mono font-medium text-white flex items-center gap-2">
                        <Globe className="h-3.5 w-3.5 text-cyan-400" />
                        <span>{scan.target_domain}</span>
                      </td>
                      <td className="py-3 capitalize text-slate-400">{scan.scan_mode}</td>
                      <td className="py-3">
                        <span className={`font-mono font-bold ${
                          scan.security_score >= 80 ? 'text-emerald-400' :
                          scan.security_score >= 60 ? 'text-amber-400' : 'text-red-400'
                        }`}>
                          {scan.security_score}/100
                        </span>
                      </td>
                      <td className="py-3">
                        <RiskBadge severity={scan.risk_level} size="sm" />
                      </td>
                      <td className="py-3">
                        <span className="font-mono text-slate-300">{scan.total_vulnerabilities}</span>
                        {scan.critical_count > 0 && (
                          <span className="ml-2 text-[10px] text-red-400">({scan.critical_count} Crit)</span>
                        )}
                      </td>
                      <td className="py-3 text-slate-500 font-mono">
                        {new Date(scan.created_at).toLocaleDateString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default Dashboard;
