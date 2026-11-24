import React from 'react';
import { AlertTriangle, ShieldAlert, AlertCircle, Info, CheckCircle2 } from 'lucide-react';

export const RiskBadge = ({ severity, size = 'md' }) => {
  const sev = (severity || 'LOW').toUpperCase();

  const configs = {
    CRITICAL: {
      bg: 'bg-red-500/15',
      text: 'text-red-400',
      border: 'border-red-500/30',
      icon: ShieldAlert,
      label: 'Critical',
    },
    HIGH: {
      bg: 'bg-orange-500/15',
      text: 'text-orange-400',
      border: 'border-orange-500/30',
      icon: AlertTriangle,
      label: 'High',
    },
    MEDIUM: {
      bg: 'bg-amber-500/15',
      text: 'text-amber-400',
      border: 'border-amber-500/30',
      icon: AlertCircle,
      label: 'Medium',
    },
    LOW: {
      bg: 'bg-emerald-500/15',
      text: 'text-emerald-400',
      border: 'border-emerald-500/30',
      icon: CheckCircle2,
      label: 'Low',
    },
    INFORMATIONAL: {
      bg: 'bg-cyan-500/15',
      text: 'text-cyan-400',
      border: 'border-cyan-500/30',
      icon: Info,
      label: 'Info',
    },
  };

  const config = configs[sev] || configs.LOW;
  const Icon = config.icon;

  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5 gap-1',
    md: 'text-xs px-2.5 py-1 gap-1.5 font-semibold',
    lg: 'text-sm px-3.5 py-1.5 gap-2 font-bold',
  };

  return (
    <span
      className={`inline-flex items-center rounded-full border ${config.bg} ${config.text} ${config.border} ${sizeClasses[size]}`}
    >
      <Icon className={size === 'sm' ? 'w-3 h-3' : 'w-3.5 h-3.5'} />
      <span>{config.label}</span>
    </span>
  );
};

export default RiskBadge;
