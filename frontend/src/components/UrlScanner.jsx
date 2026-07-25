import React, { useState } from 'react';
import { Shield, Search, Loader2 } from 'lucide-react';

export default function UrlScanner({ onResult, setLoading, loading }) {
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!url.trim()) {
      setError('Please enter a URL to scan.');
      return;
    }
    setError('');
    setLoading(true);

    try {
      const response = await fetch('https://threatlens-v5jg.onrender.com/check-url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url.trim() }),
      });

      if (!response.ok) {
        throw new Error(`Server responded with status ${response.status}`);
      }

      const data = await response.json();
      onResult(data);
    } catch (err) {
      setError(err.message || 'Failed to connect to the analysis engine.');
      onResult(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="glass-panel animate-fade-in" style={{ padding: '2rem' }}>
      <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
        <Shield size={48} style={{ color: 'var(--accent-cyan)', margin: '0 auto 1rem' }} />
        <h2 className="heading-2" style={{ marginBottom: '0.5rem' }}>URL Threat Analyzer</h2>
        <p className="text-sub">Detect phishing attempts, typosquats, and malicious domains in real-time.</p>
      </div>

      <form onSubmit={handleSubmit} style={{ maxWidth: '600px', margin: '0 auto' }}>
        <div style={{ position: 'relative', marginBottom: '1rem' }}>
          <Search size={20} style={{ position: 'absolute', left: '20px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input
            type="text"
            className="glass-input"
            style={{ paddingLeft: '3rem' }}
            placeholder="https://example.com/login"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={loading}
          />
        </div>
        
        {error && (
          <div style={{ color: 'var(--status-dangerous)', marginBottom: '1rem', fontSize: '0.9rem', textAlign: 'center' }}>
            {error}
          </div>
        )}

        <div className="flex-center">
          <button type="submit" className="glass-button" disabled={loading || !url.trim()}>
            {loading ? <Loader2 className="animate-spin" size={20} /> : <Shield size={20} />}
            {loading ? 'Analyzing...' : 'Scan URL'}
          </button>
        </div>
      </form>
    </div>
  );
}
