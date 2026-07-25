import React, { useState } from 'react';
import { Mail, Loader2, AlertCircle } from 'lucide-react';

export default function EmailScanner({ onResult, setLoading, loading }) {
  const [text, setText] = useState('');
  const [sender, setSender] = useState('');
  const [subject, setSubject] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!text.trim()) {
      setError('Email body text is required.');
      return;
    }
    setError('');
    setLoading(true);

    try {
      const response = await fetch('http://localhost:8000/check-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          text: text.trim(),
          sender: sender.trim() || undefined,
          subject: subject.trim() || undefined
        }),
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
        <Mail size={48} style={{ color: 'var(--accent-purple)', margin: '0 auto 1rem' }} />
        <h2 className="heading-2" style={{ marginBottom: '0.5rem' }}>Email Threat Analyzer</h2>
        <p className="text-sub">Detect phishing language, urgency cues, and sender typosquats.</p>
      </div>

      <form onSubmit={handleSubmit} style={{ maxWidth: '800px', margin: '0 auto' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
          <div>
            <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Sender (Optional)</label>
            <input
              type="text"
              className="glass-input"
              placeholder="support@paypal.com"
              value={sender}
              onChange={(e) => setSender(e.target.value)}
              disabled={loading}
              style={{ padding: '12px 20px' }}
            />
          </div>
          <div>
            <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Subject (Optional)</label>
            <input
              type="text"
              className="glass-input"
              placeholder="URGENT: Account Locked"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              disabled={loading}
              style={{ padding: '12px 20px' }}
            />
          </div>
        </div>

        <div style={{ marginBottom: '1rem' }}>
          <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Email Body (Required)</label>
          <textarea
            className="glass-input"
            placeholder="Paste the raw email content here..."
            value={text}
            onChange={(e) => setText(e.target.value)}
            disabled={loading}
            style={{ 
              minHeight: '200px', 
              resize: 'vertical', 
              padding: '16px 20px',
              borderRadius: 'var(--radius-lg)'
            }}
          />
        </div>
        
        {error && (
          <div style={{ color: 'var(--status-dangerous)', marginBottom: '1rem', fontSize: '0.9rem', textAlign: 'center', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}>
            <AlertCircle size={16} />
            {error}
          </div>
        )}

        <div className="flex-center">
          <button type="submit" className="glass-button" disabled={loading || !text.trim()}>
            {loading ? <Loader2 className="animate-spin" size={20} /> : <Mail size={20} />}
            {loading ? 'Analyzing Content...' : 'Scan Email'}
          </button>
        </div>
      </form>
    </div>
  );
}
