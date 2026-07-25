import React, { useState, useEffect } from 'react';
import UrlScanner from './components/UrlScanner';
import EmailScanner from './components/EmailScanner';
import RiskDashboard from './components/RiskDashboard';
import { ShieldAlert, Sun, Moon, Clock } from 'lucide-react';

function App() {
  const [activeTab, setActiveTab] = useState('url');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  
  // Theme state
  const [isLightMode, setIsLightMode] = useState(false);
  
  // History state
  const [history, setHistory] = useState(() => {
    const saved = localStorage.getItem('scanHistory');
    return saved ? JSON.parse(saved) : [];
  });

  useEffect(() => {
    if (isLightMode) {
      document.body.classList.add('light-mode');
    } else {
      document.body.classList.remove('light-mode');
    }
  }, [isLightMode]);

  const handleTabChange = (tab) => {
    setActiveTab(tab);
    setResult(null); // Clear previous results when switching
  };

  const handleResult = (newResult, target) => {
    setResult(newResult);
    if (newResult) {
      const historyItem = {
        id: Date.now(),
        type: activeTab,
        target: target,
        score: newResult.risk_score,
        classification: newResult.classification,
        timestamp: new Date().toLocaleString()
      };
      const updatedHistory = [historyItem, ...history].slice(0, 10); // Keep last 10
      setHistory(updatedHistory);
      localStorage.setItem('scanHistory', JSON.stringify(updatedHistory));
    }
  };

  const loadHistoryItem = (item) => {
    // Note: To fully reload we would need the raw data, but this just 
    // demonstrates the history functionality. For a full reload, the backend
    // would need to store reports by ID.
    alert(`Past Scan: ${item.target}\\nScore: ${item.score} (${item.classification})\\nTime: ${item.timestamp}`);
  };

  return (
    <div className="container" style={{ paddingTop: '4rem', paddingBottom: '4rem' }}>
      
      {/* Header */}
      <header style={{ textAlign: 'center', marginBottom: '3rem', position: 'relative' }}>
        <button 
          onClick={() => setIsLightMode(!isLightMode)}
          style={{
            position: 'absolute', right: 0, top: 0,
            background: 'var(--bg-glass)', border: '1px solid var(--border-glass)',
            color: 'var(--text-primary)', padding: '10px', borderRadius: '50%',
            cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center'
          }}
          title="Toggle Theme"
        >
          {isLightMode ? <Moon size={20} /> : <Sun size={20} />}
        </button>

        <div style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '16px', marginBottom: '1rem' }}>
          <div style={{ background: 'var(--bg-glass)', padding: '12px', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border-glass)', boxShadow: 'var(--glow-cyan)' }}>
            <ShieldAlert size={40} style={{ color: 'var(--accent-cyan)' }} />
          </div>
          <h1 className="heading-1 text-gradient">ThreatLens</h1>
        </div>
      </header>

      {/* Tabs */}
      <div className="tabs-container animate-fade-in">
        <button 
          className={`tab-btn ${activeTab === 'url' ? 'active' : ''}`}
          onClick={() => handleTabChange('url')}
          disabled={loading}
        >
          URL Scanner
        </button>
        <button 
          className={`tab-btn ${activeTab === 'email' ? 'active' : ''}`}
          onClick={() => handleTabChange('email')}
          disabled={loading}
        >
          Email Scanner
        </button>
      </div>

      {/* Main Content */}
      <main style={{ maxWidth: '900px', margin: '0 auto' }}>
        <div style={{ transition: 'all 0.3s ease' }}>
          {activeTab === 'url' ? (
            <UrlScanner onResult={(res) => handleResult(res, "URL Scan")} setLoading={setLoading} loading={loading} />
          ) : (
            <EmailScanner onResult={(res) => handleResult(res, "Email Scan")} setLoading={setLoading} loading={loading} />
          )}
        </div>

        {/* Results Dashboard */}
        {result && !loading && (
          <RiskDashboard result={result} />
        )}

        {/* History Log */}
        {history.length > 0 && !loading && !result && (
          <div className="glass-panel animate-fade-in delay-200" style={{ padding: '2rem', marginTop: '2rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '1.5rem' }}>
              <Clock size={24} style={{ color: 'var(--accent-purple)' }} />
              <h2 className="heading-2">Recent Scans</h2>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {history.map((item) => (
                <div 
                  key={item.id} 
                  onClick={() => loadHistoryItem(item)}
                  style={{ 
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                    padding: '16px', background: 'var(--bg-surface)', borderRadius: 'var(--radius-md)',
                    border: '1px solid var(--border-glass)', cursor: 'pointer', transition: 'all 0.2s ease'
                  }}
                  onMouseOver={(e) => e.currentTarget.style.background = 'var(--bg-surface-hover)'}
                  onMouseOut={(e) => e.currentTarget.style.background = 'var(--bg-surface)'}
                >
                  <div>
                    <div style={{ fontWeight: '600', color: 'var(--text-primary)' }}>{item.target}</div>
                    <div className="text-sub" style={{ fontSize: '0.9rem' }}>{item.timestamp}</div>
                  </div>
                  <div className={`status-badge ${item.classification.toLowerCase()}`}>
                    {item.score}/100
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>

    </div>
  );
}

export default App;
