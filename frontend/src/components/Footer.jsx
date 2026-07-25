import React from 'react';
import { ShieldAlert } from 'lucide-react';

export default function Footer({ theme }) {
  const isDark = theme === 'dark';

  return (
    <footer className={`mt-auto py-6 border-t text-xs font-mono transition-colors duration-200 ${
      isDark ? 'bg-[#0b0f19] border-slate-800 text-slate-400' : 'bg-slate-100 border-slate-200 text-slate-600'
    }`}>
      <div className="max-w-4xl mx-auto px-4 text-center flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="flex items-center space-x-2">
          <ShieldAlert className="w-4 h-4 text-cyan-500" />
          <span className="font-bold">PhishGuard Detector</span>
          <span>— Real-Time URL & Email Verification</span>
        </div>
        <div className="text-slate-500">
          <span>Engine Active</span>
        </div>
      </div>
    </footer>
  );
}
