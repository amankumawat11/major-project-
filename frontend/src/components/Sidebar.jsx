import React from 'react';
import { 
  LayoutDashboard, 
  Globe2, 
  History, 
  ShieldAlert, 
  Bot, 
  Settings, 
  Shield, 
  ExternalLink 
} from 'lucide-react';

export const Sidebar = ({ activeTab, onSelectTab }) => {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'scanner', label: 'Network Scanner', icon: Globe2 },
    { id: 'history', label: 'Scan History', icon: History },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: ShieldAlert },
    { id: 'assistant', label: 'AI Security Assistant', icon: Bot },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  return (
    <aside className="w-64 shrink-0 bg-[#0c1322] border-r border-[#19263f] flex flex-col justify-between min-h-screen relative overflow-hidden">
      {/* Brand Header */}
      <div>
        <div className="p-5 border-b border-[#19263f]">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <Shield className="h-6 w-6 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <h1 className="font-bold text-white text-base tracking-tight">SecureExplain</h1>
                <span className="text-[10px] font-bold px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">AI</span>
              </div>
              <p className="text-[11px] text-slate-400 font-medium tracking-tight">Vulnerability Auditor</p>
            </div>
          </div>
        </div>

        {/* Navigation Items */}
        <nav className="p-3 space-y-1 mt-2">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;

            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-semibold tracking-wide transition-all ${
                  isActive
                    ? 'bg-gradient-to-r from-blue-600/30 to-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-500/10'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
                }`}
              >
                <Icon className={`h-4 w-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Watermark Glowing Shield - as in visual reference */}
      <div className="p-5 relative flex flex-col items-center justify-center text-center">
        <div className="relative flex items-center justify-center py-6 opacity-30 pointer-events-none">
          <Shield className="h-28 w-28 text-cyan-400 drop-shadow-[0_0_20px_rgba(0,240,255,0.4)]" />
        </div>
        <div className="text-[11px] text-slate-500 font-mono">
          SecureExplain AI v1.0
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
