import React from 'react';
import { ShieldAlert, Sun, Moon, History, Search } from 'lucide-react';

export default function Navbar({ activePage, setActivePage, theme, setTheme, totalScans, phishingCount }) {
  const toggleTheme = () => {
    setTheme(theme === 'dark' ? 'light' : 'dark');
  };

  const isDark = theme === 'dark';

  return (
    <header className={`sticky top-0 z-50 border-b ${
      isDark ? 'bg-[#0b0f19]/90 border-slate-800 text-slate-100' : 'bg-white/90 border-slate-200 text-slate-800'
    } backdrop-blur-md transition-colors duration-200`}>
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          
          {/* Logo & Brand */}
          <div 
            className="flex items-center space-x-3 cursor-pointer select-none"
            onClick={() => setActivePage('detector')}
          >
            <div className={`flex items-center justify-center w-9 h-9 rounded-xl ${
              isDark ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/10' : 'bg-cyan-600 text-white shadow-md'
            }`}>
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <span className="text-base font-extrabold tracking-wide font-mono">PHISHGUARD</span>
              <span className={`ml-2 text-[10px] px-1.5 py-0.5 rounded font-mono font-semibold ${
                isDark ? 'bg-slate-800 text-cyan-400 border border-slate-700' : 'bg-slate-100 text-cyan-700 border border-slate-200'
              }`}>
                Detector
              </span>
            </div>
          </div>

          {/* Navigation Page Tabs */}
          <div className={`flex items-center p-1 rounded-xl border ${
            isDark ? 'bg-slate-950 border-slate-800' : 'bg-slate-100 border-slate-200'
          }`}>
            <button
              onClick={() => setActivePage('detector')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                activePage === 'detector'
                  ? isDark ? 'bg-cyan-500 text-slate-950 shadow-sm' : 'bg-white text-cyan-700 shadow-sm border border-slate-200'
                  : isDark ? 'text-slate-400 hover:text-slate-200' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Search className="w-3.5 h-3.5" />
              <span>Detector</span>
            </button>

            <button
              onClick={() => setActivePage('history')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                activePage === 'history'
                  ? isDark ? 'bg-cyan-500 text-slate-950 shadow-sm' : 'bg-white text-cyan-700 shadow-sm border border-slate-200'
                  : isDark ? 'text-slate-400 hover:text-slate-200' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <History className="w-3.5 h-3.5" />
              <span>Scan Logs</span>
              {totalScans > 0 && (
                <span className={`ml-1 px-1.5 py-0.2 text-[10px] rounded-full font-mono ${
                  activePage === 'history'
                    ? isDark ? 'bg-slate-950 text-cyan-400' : 'bg-cyan-100 text-cyan-800'
                    : isDark ? 'bg-slate-800 text-slate-300' : 'bg-slate-200 text-slate-700'
                }`}>
                  {totalScans}
                </span>
              )}
            </button>
          </div>

          {/* Theme Toggle Button */}
          <button
            onClick={toggleTheme}
            className={`p-2 rounded-xl border flex items-center space-x-1.5 text-xs font-semibold transition-all ${
              isDark
                ? 'bg-slate-900 border-slate-800 text-amber-300 hover:bg-slate-800'
                : 'bg-slate-100 border-slate-300 text-slate-700 hover:bg-slate-200'
            }`}
            title="Toggle Light/Dark Theme"
          >
            {isDark ? (
              <>
                <Sun className="w-4 h-4 text-amber-400" />
                <span className="hidden sm:inline">Light</span>
              </>
            ) : (
              <>
                <Moon className="w-4 h-4 text-indigo-600" />
                <span className="hidden sm:inline">Dark</span>
              </>
            )}
          </button>

        </div>
      </div>
    </header>
  );
}
