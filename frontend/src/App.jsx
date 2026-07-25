import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import Scanner from './components/Scanner';
import ScanHistory from './components/ScanHistory';
import Footer from './components/Footer';
import { analyzeURL, analyzeEmailText } from './utils/detectorEngine';

export default function App() {
  const [activePage, setActivePage] = useState('detector'); // 'detector' | 'history'
  const [theme, setTheme] = useState('dark'); // 'dark' | 'light'
  
  // Seed sample scan log history so user immediately sees past scans in history tab
  const [scanLogs, setScanLogs] = useState([
    analyzeURL('http://192.168.1.105/paypal-security-update/login.php?ref=account_suspend'),
    analyzeURL('https://www.paypaI-secure-update.com/verify-identity?token=948271'),
    analyzeEmailText(
      'URGENT: Account frozen in 2 hours! Click http://claim-btc-reward-free-bonus.top',
      'claims-bot@free-crypto.xyz',
      'URGENT: Your Wallet is Frozen'
    ),
    analyzeURL('https://github.com/facebook/react'),
    analyzeURL('https://www.google.com/search?q=cybersecurity')
  ]);

  const [currentResult, setCurrentResult] = useState(() => scanLogs[0]);

  useEffect(() => {
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [theme]);

  const handleScanComplete = (newResult) => {
    setScanLogs(prev => [newResult, ...prev.filter(l => l.target !== newResult.target).slice(0, 29)]);
  };

  const handleSelectScanFromHistory = (scanItem) => {
    setCurrentResult(scanItem);
    setActivePage('detector');
  };

  const phishingCount = scanLogs.filter(l => l.riskScore > 65).length;

  return (
    <div className={`min-h-screen flex flex-col font-sans transition-colors duration-200 ${
      theme === 'dark' ? 'dark-theme' : 'light-theme'
    }`}>
      {/* Header with Navigation Page Tabs and Theme Toggle */}
      <Navbar
        activePage={activePage}
        setActivePage={setActivePage}
        theme={theme}
        setTheme={setTheme}
        totalScans={scanLogs.length}
        phishingCount={phishingCount}
      />

      {/* Main Page Body */}
      <main className="flex-grow max-w-5xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activePage === 'detector' && (
          <Scanner
            theme={theme}
            onScanComplete={handleScanComplete}
            currentResult={currentResult}
            setCurrentResult={setCurrentResult}
          />
        )}

        {activePage === 'history' && (
          <ScanHistory
            theme={theme}
            scanLogs={scanLogs}
            setScanLogs={setScanLogs}
            onSelectScan={handleSelectScanFromHistory}
          />
        )}
      </main>

      {/* Footer */}
      <Footer theme={theme} />
    </div>
  );
}
