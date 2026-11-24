import React from 'react';
import { ShieldCheck, Search, Bell, Sparkles, Terminal } from 'lucide-react';

export const Navbar = ({ onQuickScan, activeTab }) => {
  const getPageTitle = () => {
    switch (activeTab) {
      case 'dashboard': return 'Cybersecurity Overview';
      case 'scanner': return 'Network & Website Scanner';
      case 'history': return 'Scan Reports & History';
      case 'vulnerabilities': return 'Vulnerability Management';
      case 'assistant': return 'AI Security Assistant';
      case 'settings': return 'System Settings';
      default: return 'SecureExplain AI';
    }
  };

  return (
    <header className="h-16 border-b border-[#19263f] bg-[#090e1a]/80 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-30">
      {/* Page Title & Breadcrumb */}
      <div className="flex items-center gap-3">
        <h2 className="text-sm font-bold text-white tracking-wide">{getPageTitle()}</h2>
        <span className="h-4 w-px bg-slate-800" />
        <div className="flex items-center gap-1.5 text-xs text-emerald-400 font-medium">
          <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
          <span>Scanner Active</span>
        </div>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-3">
        {/* Gemini AI Status Badge */}
        <div className="hidden sm:flex items-center gap-1.5 px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-300 text-xs font-semibold">
          <Sparkles className="h-3.5 w-3.5 text-indigo-400" />
          <span>Gemini GenAI Online</span>
        </div>

        {/* Quick Scan Action Button */}
        <button
          onClick={onQuickScan}
          className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold text-white bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 shadow-md shadow-indigo-600/20 transition"
        >
          <Terminal className="h-3.5 w-3.5" />
          <span>New Scan</span>
        </button>

        {/* User Avatar */}
        <div className="h-8 w-8 rounded-full bg-gradient-to-tr from-cyan-600 to-blue-500 flex items-center justify-center text-xs font-bold text-white shadow-sm">
          SE
        </div>
      </div>
    </header>
  );
};

export default Navbar;
