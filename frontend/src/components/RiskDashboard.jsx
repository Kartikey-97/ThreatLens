import React, { useEffect, useState } from 'react';
import { AlertTriangle, ShieldCheck, AlertCircle, Info, ChevronRight, Activity } from 'lucide-react';

export default function RiskDashboard({ result }) {
  const [animate, setAnimate] = useState(false);

  useEffect(() => {
    // Trigger animation slightly after mount
    const timer = setTimeout(() => setAnimate(true), 100);
    return () => clearTimeout(timer);
  }, [result]);

  if (!result) return null;

  const { risk_score, classification, ml_probability, evidence, recommendation, safe_signals } = result;

  // Determine styling based on classification
  let statusColor = 'var(--status-safe)';
  let StatusIcon = ShieldCheck;
  
  if (classification === 'suspicious') {
    statusColor = 'var(--status-suspicious)';
    StatusIcon = AlertTriangle;
  } else if (classification === 'dangerous') {
    statusColor = 'var(--status-dangerous)';
    StatusIcon = AlertCircle;
  }

  // SVG Donut Chart Logic
  const radius = 60;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = animate ? circumference - (risk_score / 100) * circumference : circumference;

  return (
    <div className="animate-fade-in delay-200" style={{ marginTop: '2rem' }}>
      <div className="glass-panel" style={{ padding: '2rem' }}>
        
        {/* Top Header Section */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '2rem', flexWrap: 'wrap', gap: '2rem' }}>
          
          {/* Score Chart */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '2rem' }}>
            <div style={{ position: 'relative', width: '140px', height: '140px' }}>
              <svg width="140" height="140" style={{ transform: 'rotate(-90deg)' }}>
                {/* Background track */}
                <circle
                  cx="70"
                  cy="70"
                  r={radius}
                  fill="none"
                  stroke="rgba(255, 255, 255, 0.05)"
                  strokeWidth="12"
                />
                {/* Animated progress */}
                <circle
                  cx="70"
                  cy="70"
                  r={radius}
                  fill="none"
                  stroke={statusColor}
                  strokeWidth="12"
                  strokeDasharray={circumference}
                  strokeDashoffset={strokeDashoffset}
                  strokeLinecap="round"
                  style={{ transition: 'stroke-dashoffset 1s cubic-bezier(0.4, 0, 0.2, 1)' }}
                />
              </svg>
              <div style={{
                position: 'absolute',
                top: 0, left: 0, width: '100%', height: '100%',
                display: 'flex', flexDirection: 'column',
                alignItems: 'center', justifyContent: 'center'
              }}>
                <span style={{ fontSize: '2.5rem', fontWeight: '700', lineHeight: '1', color: statusColor }}>
                  {animate ? risk_score : 0}
                </span>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>/100</span>
              </div>
            </div>

            <div>
              <h3 style={{ fontSize: '0.9rem', textTransform: 'uppercase', letterSpacing: '1px', color: 'var(--text-muted)', marginBottom: '4px' }}>
                Overall Risk
              </h3>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <span style={{ fontSize: '2rem', fontWeight: '600', textTransform: 'capitalize', color: 'var(--text-primary)' }}>
                  {classification}
                </span>
                <span className={`status-badge ${classification}`}>
                  <StatusIcon size={16} />
                  {classification}
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '8px', color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
                <Activity size={14} />
                ML Probability: {(ml_probability).toFixed(1)}%
              </div>
            </div>
          </div>

        </div>

        {/* AI Explanation Box */}
        {result.llm_explanation && (
          <div style={{
            background: 'var(--bg-elevated)',
            border: '1px solid var(--accent-purple)',
            padding: '1.5rem',
            borderRadius: 'var(--radius-md)',
            marginBottom: '2rem',
            boxShadow: '0 4px 20px rgba(139, 92, 246, 0.15)',
            position: 'relative',
            overflow: 'hidden'
          }}>
            <div style={{
              position: 'absolute', top: 0, left: 0, width: '4px', height: '100%',
              background: 'var(--accent-gradient)'
            }} />
            <h4 style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '0.75rem', color: 'var(--accent-cyan)' }}>
              <Info size={18} />
              AI Explanation
            </h4>
            <p style={{ color: 'var(--text-primary)', lineHeight: 1.6, fontSize: '1.05rem' }}>
              {result.llm_explanation}
            </p>
          </div>
        )}

        {/* Recommendation Box */}
        {recommendation && (
          <div style={{ 
            background: 'rgba(255, 255, 255, 0.03)', 
            borderLeft: `4px solid ${statusColor}`,
            padding: '1rem 1.5rem',
            borderRadius: '0 var(--radius-md) var(--radius-md) 0',
            marginBottom: '2rem',
            fontSize: '1.05rem'
          }}>
            {recommendation}
          </div>
        )}

        {/* Evidence & Signals Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '2rem' }}>
          
          {/* Threat Findings */}
          <div>
            <h4 style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '1rem', borderBottom: '1px solid var(--border-highlight)', paddingBottom: '0.5rem' }}>
              <AlertTriangle size={18} style={{ color: 'var(--status-suspicious)' }} />
              Analysis Findings
            </h4>
            
            {evidence && evidence.length > 0 ? (
              <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {evidence.map((item, idx) => (
                  <li key={idx} style={{ 
                    display: 'flex', gap: '12px', alignItems: 'flex-start',
                    background: 'var(--bg-surface)', padding: '12px', borderRadius: 'var(--radius-md)',
                    border: '1px solid var(--border-glass)'
                  }}>
                    {item.severity === 'critical' && <AlertCircle size={18} style={{ color: 'var(--status-dangerous)', flexShrink: 0, marginTop: '2px' }} />}
                    {item.severity === 'high' && <AlertTriangle size={18} style={{ color: 'var(--status-dangerous)', flexShrink: 0, marginTop: '2px' }} />}
                    {item.severity === 'medium' && <AlertTriangle size={18} style={{ color: 'var(--status-suspicious)', flexShrink: 0, marginTop: '2px' }} />}
                    {(item.severity === 'low' || item.severity === 'info') && <Info size={18} style={{ color: 'var(--accent-cyan)', flexShrink: 0, marginTop: '2px' }} />}
                    
                    <div>
                      <div style={{ fontSize: '0.95rem', color: 'var(--text-primary)' }}>{item.finding}</div>
                      <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-muted)', marginTop: '4px', fontWeight: 600 }}>
                        {item.severity} SEVERITY
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <div style={{ padding: '1rem', textAlign: 'center', color: 'var(--text-muted)', background: 'var(--bg-surface)', borderRadius: 'var(--radius-md)' }}>
                No threat indicators detected.
              </div>
            )}
          </div>

          {/* Safe Signals */}
          {safe_signals && safe_signals.length > 0 && (
            <div>
              <h4 style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '1rem', borderBottom: '1px solid var(--border-highlight)', paddingBottom: '0.5rem' }}>
                <ShieldCheck size={18} style={{ color: 'var(--status-safe)' }} />
                Trust Indicators
              </h4>
              <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {safe_signals.map((signal, idx) => (
                  <li key={idx} style={{ 
                    display: 'flex', gap: '12px', alignItems: 'center',
                    background: 'rgba(16, 185, 129, 0.05)', padding: '12px', borderRadius: 'var(--radius-md)',
                    border: '1px solid rgba(16, 185, 129, 0.1)'
                  }}>
                    <ChevronRight size={16} style={{ color: 'var(--status-safe)', flexShrink: 0 }} />
                    <span style={{ fontSize: '0.95rem', color: 'var(--text-primary)' }}>{signal}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

        </div>
      </div>
    </div>
  );
}
