import React from 'react';

export const StatCard = ({ title, value, icon: Icon, color = 'blue', subtitle }) => {
  const colorMap = {
    blue: {
      bg: 'from-blue-500/10 to-transparent',
      border: 'border-blue-500/20',
      iconBg: 'bg-blue-500/15',
      iconText: 'text-blue-400',
    },
    red: {
      bg: 'from-red-500/10 to-transparent',
      border: 'border-red-500/20',
      iconBg: 'bg-red-500/15',
      iconText: 'text-red-400',
    },
    orange: {
      bg: 'from-orange-500/10 to-transparent',
      border: 'border-orange-500/20',
      iconBg: 'bg-orange-500/15',
      iconText: 'text-orange-400',
    },
    amber: {
      bg: 'from-amber-500/10 to-transparent',
      border: 'border-amber-500/20',
      iconBg: 'bg-amber-500/15',
      iconText: 'text-amber-400',
    },
    emerald: {
      bg: 'from-emerald-500/10 to-transparent',
      border: 'border-emerald-500/20',
      iconBg: 'bg-emerald-500/15',
      iconText: 'text-emerald-400',
    },
    cyan: {
      bg: 'from-cyan-500/10 to-transparent',
      border: 'border-cyan-500/20',
      iconBg: 'bg-cyan-500/15',
      iconText: 'text-cyan-400',
    },
  };

  const scheme = colorMap[color] || colorMap.blue;

  return (
    <div
      className={`relative overflow-hidden rounded-xl border ${scheme.border} bg-gradient-to-b ${scheme.bg} bg-slate-900/60 p-5 shadow-lg backdrop-blur-sm transition-all duration-200 hover:scale-[1.02]`}
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-slate-400">{title}</p>
          <p className="mt-1 text-2xl font-black text-white">{value}</p>
          {subtitle && <p className="mt-1 text-xs text-slate-500">{subtitle}</p>}
        </div>
        <div className={`flex h-12 w-12 items-center justify-center rounded-xl ${scheme.iconBg}`}>
          <Icon className={`h-6 w-6 ${scheme.iconText}`} />
        </div>
      </div>
    </div>
  );
};

export default StatCard;
