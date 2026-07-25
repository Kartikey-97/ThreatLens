import React, { useState } from 'react';
import { Globe, ShieldAlert, ShieldCheck, AlertTriangle, ExternalLink, Lock, RefreshCw, X, Check, Bell } from 'lucide-react';
import { analyzeURL } from '../utils/detectorEngine';

export default function ExtensionSimulator() {
  const [currentBrowserUrl, setCurrentBrowserUrl] = useState('http://192.168.1.105/paypal-security-update/login.php');
  const [showExtensionPopup, setShowExtensionPopup] = useState(true);
  const [analysis, setAnalysis] = useState(() => analyzeURL('http://192.168.1.105/paypal-security-update/login.php'));

  const handleNavigate = (newUrl) => {
    setCurrentBrowserUrl(newUrl);
    setAnalysis(analyzeURL(newUrl));
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="cyber-card rounded-2xl p-6 border border-slate-800">
        <div className="flex items-center space-x-3 text-cyan-400 mb-2">
          <Globe className="w-6 h-6" />
          <span className="text-xs font-mono font-bold uppercase tracking-wider">BROWSER EXTENSION SIMULATOR</span>
        </div>
        <h2 className="text-2xl font-extrabold text-white">
          Real-Time Web Protection Extension
        </h2>
        <p className="mt-1 text-slate-300 text-sm">
          Simulate how the lightweight Chrome/Edge Extension actively monitors navigation and alerts users before submitting passwords on dangerous pages.
        </p>
      </div>

      {/* Simulated Web Browser UI */}
      <div className="rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl overflow-hidden max-w-4xl mx-auto">
        
        {/* Browser Top Window Bar */}
        <div className="bg-slate-950 px-4 py-3 border-b border-slate-800 flex items-center justify-between">
          
          {/* Window Control Buttons */}
          <div className="flex items-center space-x-2">
            <span className="w-3 h-3 rounded-full bg-rose-500/80 inline-block"></span>
            <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block"></span>
            <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block"></span>
          </div>

          {/* Browser Address Bar */}
          <div className="flex-1 max-w-xl mx-4 flex items-center bg-slate-900 border border-slate-800 rounded-xl px-3 py-1.5 text-xs font-mono text-slate-200">
            {analysis.riskScore > 65 ? (
              <span className="text-rose-500 flex items-center mr-2"><ShieldAlert className="w-3.5 h-3.5" /></span>
            ) : (
              <span className="text-slate-400 flex items-center mr-2"><Lock className="w-3.5 h-3.5" /></span>
            )}
            <input
              type="text"
              value={currentBrowserUrl}
              onChange={(e) => setCurrentBrowserUrl(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleNavigate(currentBrowserUrl)}
              className="w-full bg-transparent border-none focus:outline-none text-slate-200"
            />
            <button onClick={() => handleNavigate(currentBrowserUrl)} className="text-slate-500 hover:text-cyan-400">
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Extension Toolbar Icon */}
          <div className="relative">
            <button
              onClick={() => setShowExtensionPopup(!showExtensionPopup)}
              className={`p-2 rounded-lg border transition-all flex items-center space-x-1 ${
                analysis.riskScore > 65
                  ? 'bg-rose-950 border-rose-600 text-rose-300 animate-pulse'
                  : 'bg-slate-800 border-slate-700 text-cyan-400'
              }`}
              title="PhishGuard Chrome Extension Popup"
            >
              <ShieldAlert className="w-4 h-4" />
              <span className="text-[10px] font-mono font-bold px-1 rounded bg-slate-950">
                {analysis.riskScore}
              </span>
            </button>

            {/* Extension Popup Modal Overlay */}
            {showExtensionPopup && (
              <div className="absolute right-0 top-10 w-80 bg-slate-950 border border-slate-800 rounded-2xl shadow-2xl z-30 p-4 animate-scaleUp">
                
                <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-3">
                  <div className="flex items-center space-x-2">
                    <ShieldAlert className="w-4 h-4 text-cyan-400" />
                    <span className="text-xs font-mono font-bold text-white">PhishGuard Extension</span>
                  </div>
                  <button onClick={() => setShowExtensionPopup(false)} className="text-slate-500 hover:text-slate-300">
                    <X className="w-4 h-4" />
                  </button>
                </div>

                {/* Score Pill */}
                <div className={`p-3 rounded-xl border mb-3 flex items-center justify-between ${
                  analysis.riskScore > 65 ? 'bg-rose-950/40 border-rose-800 text-rose-300' : 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                }`}>
                  <div>
                    <span className="text-[10px] font-mono uppercase block text-slate-400">Current Site Status</span>
                    <span className="text-sm font-bold font-mono">{analysis.riskCategory}</span>
                  </div>
                  <span className="text-xl font-mono font-black">{analysis.riskScore}/100</span>
                </div>

                {/* Red flags summary */}
                <div className="space-y-2 text-xs">
                  <span className="text-[10px] font-mono text-slate-400 uppercase">Extension Red Flags ({analysis.redFlags.length})</span>
                  {analysis.redFlags.slice(0, 2).map((rf, idx) => (
                    <div key={idx} className="p-2 rounded bg-slate-900 text-slate-300 border border-slate-800">
                      • {rf.title}
                    </div>
                  ))}
                </div>

                <div className="mt-4 pt-3 border-t border-slate-800 text-center">
                  <span className="text-[10px] font-mono text-cyan-400">⚡ Real-Time Protection Active</span>
                </div>
              </div>
            )}
          </div>

        </div>

        {/* Webpage Content Simulation Area */}
        <div className="p-8 md:p-12 min-h-[300px] flex flex-col items-center justify-center text-center relative bg-slate-950/90">
          {analysis.riskScore > 65 ? (
            <div className="max-w-md p-6 rounded-2xl bg-rose-950/30 border border-rose-700/60 shadow-2xl">
              <ShieldAlert className="w-14 h-14 text-rose-500 mx-auto mb-3 animate-bounce" />
              <h3 className="text-xl font-bold text-rose-400">WARNING: PHISHING SITE BLOCKED</h3>
              <p className="mt-2 text-xs text-slate-300 leading-relaxed">
                PhishGuard Extension intercepted this page. It is attempting to trick you into entering credentials on an unverified domain ({analysis.target}).
              </p>
              <button
                onClick={() => handleNavigate('https://github.com')}
                className="mt-4 px-5 py-2 bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold rounded-xl shadow-lg transition-all"
              >
                Back to Safety
              </button>
            </div>
          ) : (
            <div className="max-w-md p-6 rounded-2xl bg-slate-900 border border-slate-800">
              <ShieldCheck className="w-12 h-12 text-emerald-400 mx-auto mb-3" />
              <h3 className="text-lg font-bold text-emerald-400">Verified Safe Web Domain</h3>
              <p className="mt-1 text-xs text-slate-400">
                SSL Certificate verified and no malicious threat vectors detected.
              </p>
            </div>
          )}
        </div>

      </div>
    </div>
  );
}
