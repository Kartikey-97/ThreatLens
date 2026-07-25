import React, { useState } from 'react';
import { 
  Link, Mail, ShieldAlert, ShieldCheck, AlertTriangle, 
  RefreshCw, CheckCircle2, AlertOctagon, ArrowRight, Copy, Check, Zap, X
} from 'lucide-react';
import { PRESET_SAMPLES, analyzeURL, analyzeEmailText } from '../utils/detectorEngine';

export default function Scanner({ theme, onScanComplete, currentResult, setCurrentResult }) {
  const [scanType, setScanType] = useState('url'); // 'url' | 'email'
  const [urlInput, setUrlInput] = useState('http://192.168.1.105/paypal-security-update/login.php?ref=account_suspend');
  const [emailSender, setEmailSender] = useState('');
  const [emailSubject, setEmailSubject] = useState('');
  const [emailContent, setEmailContent] = useState('');
  
  const [isScanning, setIsScanning] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleScan = (e) => {
    if (e) e.preventDefault();
    if (scanType === 'url' && !urlInput.trim()) return;
    if (scanType === 'email' && !emailContent.trim()) return;

    setIsScanning(true);
    setCurrentResult(null);

    setTimeout(() => {
      let result;
      if (scanType === 'url') {
        result = analyzeURL(urlInput);
      } else {
        result = analyzeEmailText(emailContent, emailSender, emailSubject);
      }

      setIsScanning(false);
      setCurrentResult(result);
      if (onScanComplete) {
        onScanComplete(result);
      }
    }, 400);
  };

  const handleLoadSample = (sample) => {
    if (sample.type === 'url') {
      setScanType('url');
      setUrlInput(sample.url);
      const res = analyzeURL(sample.url);
      setCurrentResult(res);
      if (onScanComplete) onScanComplete(res);
    } else {
      setScanType('email');
      setEmailSender(sample.sender || '');
      setEmailSubject(sample.subject || '');
      setEmailContent(sample.content || '');
      const res = analyzeEmailText(sample.content, sample.sender, sample.subject);
      setCurrentResult(res);
      if (onScanComplete) onScanComplete(res);
    }
  };

  const copyResult = () => {
    if (!currentResult) return;
    const text = `PhishGuard Result:\nTarget: ${currentResult.target}\nStatus: ${currentResult.riskCategory} (Risk Score: ${currentResult.riskScore}/100)`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isDark = theme === 'dark';

  return (
    <div className="space-y-6 max-w-3xl mx-auto py-4">
      {/* Title & Description Header */}
      <div className="text-center">
        <h1 className={`text-2xl sm:text-3xl font-extrabold tracking-tight ${isDark ? 'text-white' : 'text-slate-900'}`}>
          Phishing & Malicious Link/Email Detector
        </h1>
        <p className={`mt-2 text-sm max-w-xl mx-auto ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
          Check any URL or email text to verify if it is valid & safe or a dangerous phishing attempt.
        </p>
      </div>

      {/* Main Single Card */}
      <div className={`rounded-2xl p-6 sm:p-8 transition-colors duration-200 ${
        isDark ? 'clean-card-dark' : 'clean-card-light'
      }`}>
        
        {/* INPUT TOGGLE (URL vs EMAIL) */}
        <div className="mb-6">
          <label className={`block text-xs font-semibold uppercase tracking-wider mb-2 font-mono ${
            isDark ? 'text-slate-400' : 'text-slate-600'
          }`}>
            Select Input Type:
          </label>
          <div className={`p-1.5 rounded-xl flex items-center space-x-2 border ${
            isDark ? 'bg-slate-950 border-slate-800' : 'bg-slate-100 border-slate-200'
          }`}>
            <button
              type="button"
              onClick={() => setScanType('url')}
              className={`flex-1 py-2.5 px-4 rounded-lg text-sm font-semibold flex items-center justify-center space-x-2 transition-all ${
                scanType === 'url'
                  ? isDark ? 'bg-cyan-500 text-slate-950 shadow-sm' : 'bg-cyan-600 text-white shadow-sm'
                  : isDark ? 'text-slate-400 hover:text-slate-200' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Link className="w-4 h-4" />
              <span>URL Link</span>
            </button>

            <button
              type="button"
              onClick={() => setScanType('email')}
              className={`flex-1 py-2.5 px-4 rounded-lg text-sm font-semibold flex items-center justify-center space-x-2 transition-all ${
                scanType === 'email'
                  ? isDark ? 'bg-cyan-500 text-slate-950 shadow-sm' : 'bg-cyan-600 text-white shadow-sm'
                  : isDark ? 'text-slate-400 hover:text-slate-200' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Mail className="w-4 h-4" />
              <span>Email Content</span>
            </button>
          </div>
        </div>

        {/* INPUT FORM */}
        <form onSubmit={handleScan} className="space-y-4">
          {scanType === 'url' ? (
            <div>
              <label className={`block text-xs font-semibold uppercase mb-1.5 ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                URL / Web Address
              </label>
              <div className="relative">
                <input
                  type="text"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  placeholder="Enter URL e.g. https://example.com/login"
                  className={`w-full px-4 py-3 rounded-xl text-sm font-mono focus:outline-none transition-all ${
                    isDark
                      ? 'bg-slate-950 border border-slate-700 text-slate-100 placeholder-slate-500 focus:border-cyan-500'
                      : 'bg-white border border-slate-300 text-slate-900 placeholder-slate-400 focus:border-cyan-600'
                  }`}
                  required
                />
              </div>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className={`block text-xs font-semibold uppercase mb-1 ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                    Sender Email (Optional)
                  </label>
                  <input
                    type="text"
                    value={emailSender}
                    onChange={(e) => setEmailSender(e.target.value)}
                    placeholder="e.g. security@verify-bank.com"
                    className={`w-full px-3.5 py-2.5 rounded-xl text-sm font-mono focus:outline-none ${
                      isDark
                        ? 'bg-slate-950 border border-slate-700 text-slate-100 placeholder-slate-500 focus:border-cyan-500'
                        : 'bg-white border border-slate-300 text-slate-900 placeholder-slate-400 focus:border-cyan-600'
                    }`}
                  />
                </div>
                <div>
                  <label className={`block text-xs font-semibold uppercase mb-1 ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                    Subject Line (Optional)
                  </label>
                  <input
                    type="text"
                    value={emailSubject}
                    onChange={(e) => setEmailSubject(e.target.value)}
                    placeholder="e.g. Action Required: Account Notice"
                    className={`w-full px-3.5 py-2.5 rounded-xl text-sm focus:outline-none ${
                      isDark
                        ? 'bg-slate-950 border border-slate-700 text-slate-100 placeholder-slate-500 focus:border-cyan-500'
                        : 'bg-white border border-slate-300 text-slate-900 placeholder-slate-400 focus:border-cyan-600'
                    }`}
                  />
                </div>
              </div>

              <div>
                <label className={`block text-xs font-semibold uppercase mb-1 ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                  Email Message Text
                </label>
                <textarea
                  rows={4}
                  value={emailContent}
                  onChange={(e) => setEmailContent(e.target.value)}
                  placeholder="Paste the suspicious email text here..."
                  className={`w-full p-3 rounded-xl text-sm focus:outline-none ${
                    isDark
                      ? 'bg-slate-950 border border-slate-700 text-slate-100 placeholder-slate-500 focus:border-cyan-500'
                      : 'bg-white border border-slate-300 text-slate-900 placeholder-slate-400 focus:border-cyan-600'
                  }`}
                  required
                />
              </div>
            </div>
          )}

          {/* Action Button */}
          <div className="pt-2 flex items-center justify-between">
            <button
              type="submit"
              disabled={isScanning}
              className={`w-full py-3 px-6 rounded-xl font-bold text-sm flex items-center justify-center space-x-2 transition-all ${
                isDark
                  ? 'bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-md'
                  : 'bg-cyan-600 hover:bg-cyan-700 text-white shadow-md'
              } disabled:opacity-50`}
            >
              {isScanning ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Checking...</span>
                </>
              ) : (
                <>
                  <span>Check Validity & Safety</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </div>
        </form>

        {/* Quick Demo Preset Pills */}
        <div className="mt-6 pt-4 border-t border-slate-200 dark:border-slate-800">
          <span className={`text-xs font-mono font-semibold block mb-2 ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
            ⚡ TRY A SAMPLE TEST CASE:
          </span>
          <div className="flex flex-wrap gap-2">
            {PRESET_SAMPLES.urls.slice(0, 3).map((sample) => (
              <button
                key={sample.id}
                onClick={() => handleLoadSample(sample)}
                className={`text-xs px-3 py-1.5 rounded-lg border transition-all ${
                  isDark
                    ? 'bg-slate-900 border-slate-800 text-slate-300 hover:bg-slate-800 hover:border-slate-700'
                    : 'bg-slate-50 border-slate-200 text-slate-700 hover:bg-slate-100 hover:border-slate-300'
                }`}
              >
                {sample.title}
              </button>
            ))}
            {PRESET_SAMPLES.emails.slice(0, 1).map((sample) => (
              <button
                key={sample.id}
                onClick={() => handleLoadSample(sample)}
                className={`text-xs px-3 py-1.5 rounded-lg border transition-all ${
                  isDark
                    ? 'bg-slate-900 border-slate-800 text-slate-300 hover:bg-slate-800 hover:border-slate-700'
                    : 'bg-slate-50 border-slate-200 text-slate-700 hover:bg-slate-100 hover:border-slate-300'
                }`}
              >
                {sample.title}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* SCAN RESULT OUTPUT */}
      {currentResult && !isScanning && (
        <div className={`rounded-2xl p-6 sm:p-8 border transition-all ${
          currentResult.riskScore > 65
            ? isDark ? 'bg-rose-950/20 border-rose-800' : 'bg-rose-50 border-rose-200'
            : currentResult.riskScore > 25
            ? isDark ? 'bg-amber-950/20 border-amber-800' : 'bg-amber-50 border-amber-200'
            : isDark ? 'bg-emerald-950/20 border-emerald-800' : 'bg-emerald-50 border-emerald-200'
        }`}>
          
          {/* Status Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4 mb-6 border-slate-200 dark:border-slate-800">
            <div className="flex items-center space-x-3">
              {currentResult.riskScore > 65 ? (
                <div className="w-10 h-10 rounded-full bg-rose-500 text-white flex items-center justify-center flex-shrink-0">
                  <ShieldAlert className="w-6 h-6" />
                </div>
              ) : currentResult.riskScore > 25 ? (
                <div className="w-10 h-10 rounded-full bg-amber-500 text-slate-950 flex items-center justify-center flex-shrink-0">
                  <AlertTriangle className="w-6 h-6" />
                </div>
              ) : (
                <div className="w-10 h-10 rounded-full bg-emerald-500 text-slate-950 flex items-center justify-center flex-shrink-0">
                  <ShieldCheck className="w-6 h-6" />
                </div>
              )}

              <div>
                <span className={`text-xs font-mono font-bold uppercase tracking-wider ${
                  currentResult.riskScore > 65 ? 'text-rose-500' : currentResult.riskScore > 25 ? 'text-amber-500' : 'text-emerald-600'
                }`}>
                  RESULT VERIFICATION:
                </span>
                <h2 className={`text-xl font-black ${
                  currentResult.riskScore > 65
                    ? isDark ? 'text-rose-400' : 'text-rose-700'
                    : currentResult.riskScore > 25
                    ? isDark ? 'text-amber-400' : 'text-amber-700'
                    : isDark ? 'text-emerald-400' : 'text-emerald-700'
                }`}>
                  {currentResult.riskScore > 65
                    ? 'INVALID & MALICIOUS (PHISHING DETECTED)'
                    : currentResult.riskScore > 25
                    ? 'SUSPICIOUS (PROCEED WITH CAUTION)'
                    : 'VALID & SAFE TO USE'}
                </h2>
              </div>
            </div>

            {/* Risk Score Pill */}
            <div className="flex items-center space-x-3">
              <div className={`px-4 py-2 rounded-xl text-center font-mono border ${
                isDark ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'
              }`}>
                <span className="text-xs text-slate-500 block uppercase">Risk Score</span>
                <span className={`text-lg font-bold ${
                  currentResult.riskScore > 65 ? 'text-rose-500' : currentResult.riskScore > 25 ? 'text-amber-500' : 'text-emerald-500'
                }`}>
                  {currentResult.riskScore} / 100
                </span>
              </div>

              <button
                onClick={copyResult}
                className={`p-2.5 rounded-xl border text-xs flex items-center space-x-1.5 transition-all ${
                  isDark ? 'bg-slate-900 border-slate-800 hover:bg-slate-800 text-slate-300' : 'bg-white border-slate-200 hover:bg-slate-50 text-slate-700'
                }`}
                title="Copy Summary"
              >
                {copied ? <Check className="w-4 h-4 text-emerald-500" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {/* Details & Target */}
          <div className="mb-6">
            <p className={`text-xs font-mono break-all ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
              Scanned Target: <span className={`font-semibold ${isDark ? 'text-slate-200' : 'text-slate-900'}`}>{currentResult.target}</span>
            </p>
          </div>

          {/* Red Flags / Reasons List */}
          <div className="space-y-4">
            <h3 className={`text-sm font-bold uppercase tracking-wider font-mono ${isDark ? 'text-slate-300' : 'text-slate-800'}`}>
              Analysis Explanation ({currentResult.redFlags.length} Risk Factors)
            </h3>

            {currentResult.redFlags.length === 0 ? (
              <div className={`p-4 rounded-xl border flex items-center space-x-3 ${
                isDark ? 'bg-emerald-950/30 border-emerald-900/40 text-emerald-300' : 'bg-emerald-50 border-emerald-200 text-emerald-800'
              }`}>
                <CheckCircle2 className="w-5 h-5 text-emerald-500 flex-shrink-0" />
                <span className="text-xs font-medium">
                  No structural red flags, homograph attacks, typosquatting, or urgency manipulation detected.
                </span>
              </div>
            ) : (
              <div className="space-y-2.5">
                {currentResult.redFlags.map((flag, idx) => (
                  <div
                    key={idx}
                    className={`p-3.5 rounded-xl border text-xs transition-all ${
                      isDark
                        ? 'bg-slate-900/90 border-slate-800 text-slate-300'
                        : 'bg-white border-slate-200 text-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between font-semibold mb-1">
                      <span className="flex items-center space-x-2 text-rose-500">
                        <AlertOctagon className="w-4 h-4 flex-shrink-0" />
                        <span>{flag.title}</span>
                      </span>
                      <span className={`text-[10px] uppercase font-mono px-2 py-0.5 rounded ${
                        flag.severity === 'critical' ? 'bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300' : 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300'
                      }`}>
                        {flag.severity}
                      </span>
                    </div>
                    <p className={`text-xs leading-relaxed ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
                      {flag.detail}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Safety Recommendation Box */}
          <div className={`mt-6 p-4 rounded-xl border text-xs font-medium ${
            currentResult.riskScore > 65
              ? isDark ? 'bg-rose-950/40 border-rose-900 text-rose-200' : 'bg-rose-100 border-rose-300 text-rose-900'
              : currentResult.riskScore > 25
              ? isDark ? 'bg-amber-950/40 border-amber-900 text-amber-200' : 'bg-amber-100 border-amber-300 text-amber-900'
              : isDark ? 'bg-emerald-950/40 border-emerald-900 text-emerald-200' : 'bg-emerald-100 border-emerald-300 text-emerald-900'
          }`}>
            <span className="font-bold block uppercase mb-1">Recommendation:</span>
            {currentResult.riskScore > 65 ? (
              <span>🚨 <strong>DO NOT CLICK OR SUBMIT DATA.</strong> This link/email displays clear indicators of a malicious phishing attack aimed at stealing your credentials or personal information.</span>
            ) : currentResult.riskScore > 25 ? (
              <span>⚠️ <strong>EXERCISE CAUTION.</strong> Some suspicious patterns were detected. Verify the sender or domain independently before clicking.</span>
            ) : (
              <span>✅ <strong>SAFE TO USE.</strong> No threat indicators detected.</span>
            )}
          </div>

        </div>
      )}
    </div>
  );
}
