import React from 'react';
import { Cpu, ShieldCheck, Sliders, Layers, Database, Lock, AlertTriangle, Code2 } from 'lucide-react';

export default function ThreatEngineBreakdown() {
  const heuristicsList = [
    {
      name: 'IDN Homograph Spoofing Check',
      weight: 'High (35 pts)',
      description: 'Detects mixed Cyrillic/Greek Unicode lookalike glyphs mimicking legitimate corporate domains (e.g. gооgle.com using Cyrillic "о").'
    },
    {
      name: 'Raw IP Hostname Detection',
      weight: 'Critical (40 pts)',
      description: 'Flags URLs relying on raw IP addresses (e.g. http://192.168.1.100/login) instead of standard DNS records.'
    },
    {
      name: 'Levenshtein Typosquatting Distance',
      weight: 'High (30 pts)',
      description: 'Measures string edit distance against top 500 Alexa/Tranco brand domains (e.g. paypaI-security.com).'
    },
    {
      name: 'HTTPS & SSL Encryption Verification',
      weight: 'Medium (20 pts)',
      description: 'Checks for plain HTTP protocol vs valid SSL/TLS certificates and TLS handshake validity.'
    },
    {
      name: 'Subdomain Stacking & Hyphen Density',
      weight: 'Medium (20 pts)',
      description: 'Analyzes subdomains stacked > 3 levels deep (e.g. account.login.paypal.attacker-domain.xyz).'
    },
    {
      name: 'NLP Urgency & Panic Triggers',
      weight: 'High (30 pts)',
      description: 'Parses email body for high-pressure social engineering keywords ("Account Frozen in 2h", "Verify SSN").'
    }
  ];

  const mlPipeline = [
    {
      step: '01. Feature Extraction',
      details: 'Extracts 42 quantitative vectors: Domain Age, Subdomain Entropy, TLD Reputation, URL Length, Query Params, NLP Sentiment.'
    },
    {
      step: '02. Random Forest / LightGBM Classifier',
      details: 'Evaluates vector set against a model trained on 250,000+ PhishTank & OpenPhish malicious sample feeds.'
    },
    {
      step: '03. Risk Score Fusion',
      details: 'Combines heuristic rule violations (60% weight) with ML probabilistic confidence (40% weight) into a 0-100 risk score.'
    }
  ];

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Header */}
      <div className="cyber-card rounded-2xl p-6 md:p-8 border border-slate-800">
        <div className="flex items-center space-x-3 text-cyan-400 mb-2">
          <Cpu className="w-6 h-6 animate-pulse" />
          <span className="text-xs font-mono font-bold uppercase tracking-wider">THREAT DETECTION ARCHITECTURE</span>
        </div>
        <h2 className="text-2xl md:text-3xl font-extrabold text-white">
          Hybrid Heuristics + Trained ML Classifier
        </h2>
        <p className="mt-2 text-slate-300 text-sm max-w-3xl leading-relaxed">
          PhishGuard AI uses a dual-engine architecture combining strict deterministic security rules with machine learning probabilistic sentiment analysis to ensure zero false positives for legitimate services while catching zero-day phishing attacks.
        </p>
      </div>

      {/* Grid of Heuristic Features */}
      <div>
        <h3 className="text-lg font-bold text-slate-100 mb-4 flex items-center space-x-2">
          <Layers className="w-5 h-5 text-cyan-400" />
          <span>Rule-Based Heuristic Inspection Engine</span>
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {heuristicsList.map((item, idx) => (
            <div key={idx} className="cyber-card rounded-xl p-5 border border-slate-800 hover:border-cyan-500/40 transition-all">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-mono font-bold text-slate-300 px-2 py-0.5 rounded bg-slate-900 border border-slate-800">
                  {item.weight}
                </span>
                <ShieldCheck className="w-4 h-4 text-cyan-400" />
              </div>
              <h4 className="font-bold text-slate-100 text-sm mb-1">{item.name}</h4>
              <p className="text-xs text-slate-400 leading-relaxed">{item.description}</p>
            </div>
          ))}
        </div>
      </div>

      {/* ML Pipeline Flow */}
      <div className="cyber-card rounded-2xl p-6 border border-slate-800">
        <h3 className="text-lg font-bold text-slate-100 mb-4 flex items-center space-x-2">
          <Database className="w-5 h-5 text-cyan-400" />
          <span>Machine Learning Pipeline Execution</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {mlPipeline.map((p, i) => (
            <div key={i} className="p-4 rounded-xl bg-slate-950/80 border border-slate-800">
              <span className="text-xs font-mono text-cyan-400 font-bold block mb-1">{p.step}</span>
              <p className="text-xs text-slate-300 leading-relaxed">{p.details}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Model Performance Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="cyber-card rounded-xl p-4 border border-slate-800 text-center">
          <span className="text-2xl font-extrabold font-mono text-cyan-400">99.4%</span>
          <span className="block text-xs text-slate-400 font-mono mt-1">Classification Precision</span>
        </div>
        <div className="cyber-card rounded-xl p-4 border border-slate-800 text-center">
          <span className="text-2xl font-extrabold font-mono text-emerald-400">&lt; 15ms</span>
          <span className="block text-xs text-slate-400 font-mono mt-1">Real-Time Latency</span>
        </div>
        <div className="cyber-card rounded-xl p-4 border border-slate-800 text-center">
          <span className="text-2xl font-extrabold font-mono text-indigo-400">250,000+</span>
          <span className="block text-xs text-slate-400 font-mono mt-1">Trained Datasets</span>
        </div>
        <div className="cyber-card rounded-xl p-4 border border-slate-800 text-center">
          <span className="text-2xl font-extrabold font-mono text-rose-400">0.02%</span>
          <span className="block text-xs text-slate-400 font-mono mt-1">False Positive Rate</span>
        </div>
      </div>
    </div>
  );
}
