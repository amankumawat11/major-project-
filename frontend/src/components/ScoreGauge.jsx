import React from 'react';

export const ScoreGauge = ({ score = 100, riskLevel = 'LOW' }) => {
  // Score is between 0 and 100
  const normalizedScore = Math.min(100, Math.max(0, score));

  // Determine color based on score
  let strokeColor = '#10b981'; // Green
  let labelText = 'Low Risk';
  let labelColor = 'text-emerald-400';

  if (normalizedScore < 40) {
    strokeColor = '#ef4444'; // Red
    labelText = 'Critical Risk';
    labelColor = 'text-red-400';
  } else if (normalizedScore < 65) {
    strokeColor = '#f97316'; // Orange
    labelText = 'High Risk';
    labelColor = 'text-orange-400';
  } else if (normalizedScore < 85) {
    strokeColor = '#eab308'; // Amber
    labelText = 'Moderate Risk';
    labelColor = 'text-amber-400';
  }

  // Semi-circle SVG calculation
  // Radius = 60, circumference for half circle = Math.PI * 60 ~= 188.5
  const radius = 55;
  const arcLength = Math.PI * radius;
  const offset = arcLength - (normalizedScore / 100) * arcLength;

  return (
    <div className="flex flex-col items-center justify-center p-3">
      <div className="relative w-36 h-20 flex items-center justify-center">
        <svg className="w-36 h-36 -rotate-180 transform" viewBox="0 0 140 140">
          {/* Background Arc */}
          <path
            d="M 15,70 A 55,55 0 0,1 125,70"
            fill="none"
            stroke="#1e293b"
            strokeWidth="12"
            strokeLinecap="round"
          />
          {/* Foreground Colored Arc */}
          <path
            d="M 15,70 A 55,55 0 0,1 125,70"
            fill="none"
            stroke={strokeColor}
            strokeWidth="12"
            strokeDasharray={arcLength}
            strokeDashoffset={offset}
            strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 1s ease-in-out' }}
          />
        </svg>

        {/* Center score text */}
        <div className="absolute top-7 flex flex-col items-center">
          <span className="text-2xl font-black tracking-tight text-white">
            {normalizedScore}
            <span className="text-xs font-normal text-slate-400">/100</span>
          </span>
        </div>
      </div>

      <div className={`mt-1 text-xs font-semibold tracking-wide ${labelColor}`}>
        {labelText}
      </div>
    </div>
  );
};

export default ScoreGauge;
