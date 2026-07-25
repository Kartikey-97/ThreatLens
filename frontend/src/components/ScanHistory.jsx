import React, { useState } from 'react';
import { 
  History, Download, Trash2, Search, ExternalLink, 
  ShieldAlert, ShieldCheck, AlertTriangle, ArrowRight, Filter
} from 'lucide-react';

export default function ScanHistory({ theme, scanLogs, setScanLogs, onSelectScan }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterRisk, setFilterRisk] = useState('ALL');

  const isDark = theme === 'dark';

  const filteredLogs = scanLogs.filter(log => {
    const matchesSearch = log.target.toLowerCase().includes(searchTerm.toLowerCase());
    if (filterRisk === 'ALL') return matchesSearch;
    if (filterRisk === 'PHISHING') return matchesSearch && log.riskScore > 65;
    if (filterRisk === 'SUSPICIOUS') return matchesSearch && log.riskScore > 25 && log.riskScore <= 65;
    if (filterRisk === 'SAFE') return matchesSearch && log.riskScore <= 25;
    return matchesSearch;
  });

  const totalScans = scanLogs.length;
  const safeCount = scanLogs.filter(l => l.riskScore <= 25).length;
  const phishingCount = scanLogs.filter(l => l.riskScore > 65).length;
  const suspiciousCount = scanLogs.filter(l => l.riskScore > 25 && l.riskScore <= 65).length;

  const exportLogsJSON = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(scanLogs, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `phishguard_scan_history_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const removeLogItem = (idOrIndex) => {
    setScanLogs(prev => prev.filter((_, idx) => idx !== idOrIndex));
  };

  const clearLogs = () => {
    if (window.confirm("Are you sure you want to clear all scan history logs?")) {
      setScanLogs([]);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto py-4 animate-fadeIn">
      {/* Title & Actions Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <History className="w-5 h-5 text-cyan-500" />
            <h1 className={`text-2xl font-extrabold tracking-tight ${isDark ? 'text-white' : 'text-slate-900'}`}>
              Scan History Logs
            </h1>
          </div>
          <p className={`mt-1 text-xs ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
            Audit trail of verified URLs and email text analyses.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          {scanLogs.length > 0 && (
            <>
              <button
                onClick={exportLogsJSON}
                className={`px-3.5 py-2 rounded-xl border text-xs font-semibold flex items-center space-x-1.5 transition-all ${
                  isDark
                    ? 'bg-slate-900 border-slate-800 text-slate-200 hover:bg-slate-800'
                    : 'bg-white border-slate-300 text-slate-700 hover:bg-slate-50'
                }`}
              >
                <Download className="w-3.5 h-3.5 text-cyan-500" />
                <span>Export JSON</span>
              </button>
              
              <button
                onClick={clearLogs}
                className={`px-3.5 py-2 rounded-xl border text-xs font-semibold flex items-center space-x-1.5 transition-all ${
                  isDark
                    ? 'bg-slate-900 border-slate-800 text-slate-400 hover:text-rose-400 hover:border-rose-900'
                    : 'bg-white border-slate-300 text-slate-600 hover:text-rose-600 hover:border-rose-200'
                }`}
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Clear</span>
              </button>
            </>
          )}
        </div>
      </div>

      {/* Summary Stat Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className={`p-4 rounded-xl border ${isDark ? 'clean-card-dark' : 'clean-card-light'}`}>
          <span className={`text-xs font-mono uppercase block ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Total Scans</span>
          <span className={`text-2xl font-extrabold font-mono mt-1 block ${isDark ? 'text-slate-100' : 'text-slate-900'}`}>{totalScans}</span>
        </div>

        <div className={`p-4 rounded-xl border ${isDark ? 'clean-card-dark' : 'clean-card-light'}`}>
          <span className={`text-xs font-mono uppercase block ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Safe Targets</span>
          <span className="text-2xl font-extrabold font-mono mt-1 block text-emerald-500">{safeCount}</span>
        </div>

        <div className={`p-4 rounded-xl border ${isDark ? 'clean-card-dark' : 'clean-card-light'}`}>
          <span className={`text-xs font-mono uppercase block ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Malicious Flagged</span>
          <span className="text-2xl font-extrabold font-mono mt-1 block text-rose-500">{phishingCount}</span>
        </div>

        <div className={`p-4 rounded-xl border ${isDark ? 'clean-card-dark' : 'clean-card-light'}`}>
          <span className={`text-xs font-mono uppercase block ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Suspicious</span>
          <span className="text-2xl font-extrabold font-mono mt-1 block text-amber-500">{suspiciousCount}</span>
        </div>
      </div>

      {/* Filters Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
        {/* Search input */}
        <div className="relative w-full sm:w-72">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by URL or keyword..."
            className={`w-full pl-9 pr-3 py-2 rounded-xl text-xs focus:outline-none transition-all ${
              isDark
                ? 'bg-slate-950 border border-slate-800 text-slate-200 placeholder-slate-500 focus:border-cyan-500'
                : 'bg-white border border-slate-300 text-slate-900 placeholder-slate-400 focus:border-cyan-600'
            }`}
          />
        </div>

        {/* Filter chips */}
        <div className={`flex items-center p-1 rounded-xl border text-xs font-semibold ${
          isDark ? 'bg-slate-950 border-slate-800' : 'bg-slate-100 border-slate-200'
        }`}>
          {[
            { id: 'ALL', label: 'All' },
            { id: 'SAFE', label: 'Safe Only' },
            { id: 'PHISHING', label: 'Malicious Only' },
            { id: 'SUSPICIOUS', label: 'Suspicious' }
          ].map(f => (
            <button
              key={f.id}
              onClick={() => setFilterRisk(f.id)}
              className={`px-3 py-1.5 rounded-lg transition-all ${
                filterRisk === f.id
                  ? isDark ? 'bg-cyan-500 text-slate-950 shadow-sm' : 'bg-white text-cyan-700 shadow-sm border border-slate-200'
                  : isDark ? 'text-slate-400 hover:text-slate-200' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>

      {/* Logs Table / Cards List */}
      <div className={`rounded-2xl border overflow-hidden ${
        isDark ? 'clean-card-dark' : 'clean-card-light'
      }`}>
        {filteredLogs.length === 0 ? (
          <div className="p-12 text-center text-slate-500 text-sm">
            No scan logs match your search or filter.
          </div>
        ) : (
          <div className="divide-y divide-slate-200 dark:divide-slate-800/80">
            {filteredLogs.map((log, idx) => (
              <div 
                key={idx} 
                className={`p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 transition-colors ${
                  isDark ? 'hover:bg-slate-900/60' : 'hover:bg-slate-50'
                }`}
              >
                {/* Left: Status Badge & Target Info */}
                <div className="flex items-start space-x-3.5 max-w-xl">
                  {log.riskScore > 65 ? (
                    <div className="w-8 h-8 rounded-lg bg-rose-500/10 text-rose-500 border border-rose-500/30 flex items-center justify-center flex-shrink-0 mt-0.5">
                      <ShieldAlert className="w-4 h-4" />
                    </div>
                  ) : log.riskScore > 25 ? (
                    <div className="w-8 h-8 rounded-lg bg-amber-500/10 text-amber-500 border border-amber-500/30 flex items-center justify-center flex-shrink-0 mt-0.5">
                      <AlertTriangle className="w-4 h-4" />
                    </div>
                  ) : (
                    <div className="w-8 h-8 rounded-lg bg-emerald-500/10 text-emerald-500 border border-emerald-500/30 flex items-center justify-center flex-shrink-0 mt-0.5">
                      <ShieldCheck className="w-4 h-4" />
                    </div>
                  )}

                  <div className="space-y-0.5">
                    <div className="flex items-center space-x-2">
                      <span className={`text-xs font-bold font-mono ${
                        log.riskScore > 65 ? 'text-rose-500' : log.riskScore > 25 ? 'text-amber-500' : 'text-emerald-600'
                      }`}>
                        {log.riskScore > 65 ? 'MALICIOUS / PHISHING' : log.riskScore > 25 ? 'SUSPICIOUS' : 'VALID & SAFE'}
                      </span>
                      <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded border ${
                        isDark ? 'bg-slate-950 border-slate-800 text-slate-400' : 'bg-slate-100 border-slate-200 text-slate-600'
                      }`}>
                        {log.type}
                      </span>
                    </div>

                    <p className={`text-xs font-mono break-all font-medium ${isDark ? 'text-slate-200' : 'text-slate-800'}`}>
                      {log.target}
                    </p>

                    <div className="flex items-center space-x-3 text-[11px] text-slate-400 font-mono pt-0.5">
                      <span>Flags: {log.redFlags.length}</span>
                      <span>•</span>
                      <span>Time: {log.timestamp}</span>
                    </div>
                  </div>
                </div>

                {/* Right: Score & Actions */}
                <div className="flex items-center space-x-3 self-end sm:self-center">
                  <div className="text-right">
                    <span className="text-[10px] font-mono text-slate-400 block uppercase">Risk Score</span>
                    <span className={`text-sm font-bold font-mono ${
                      log.riskScore > 65 ? 'text-rose-500' : log.riskScore > 25 ? 'text-amber-500' : 'text-emerald-500'
                    }`}>
                      {log.riskScore}/100
                    </span>
                  </div>

                  <button
                    onClick={() => onSelectScan(log)}
                    className={`px-3 py-1.5 rounded-lg border text-xs font-semibold flex items-center space-x-1 transition-all ${
                      isDark
                        ? 'bg-slate-900 border-slate-800 text-cyan-400 hover:bg-slate-800'
                        : 'bg-white border-slate-300 text-cyan-700 hover:bg-slate-50'
                    }`}
                  >
                    <span>Inspect</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>

                  <button
                    onClick={() => removeLogItem(idx)}
                    className={`p-1.5 rounded-lg text-slate-400 hover:text-rose-500 transition-colors`}
                    title="Remove item"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>

              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
