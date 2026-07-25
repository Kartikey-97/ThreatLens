// Advanced Heuristic + ML Detection Engine Simulation for Phishing & Malicious URLs/Emails

// List of pre-configured sample URLs & Emails for instant demo testing
export const PRESET_SAMPLES = {
  urls: [
    {
      id: 'sample-phish-1',
      title: '🚨 Fake Bank Verification',
      url: 'http://192.168.1.105/paypal-security-update/login.php?ref=account_suspend',
      type: 'url'
    },
    {
      id: 'sample-phish-2',
      title: '⚠️ Typosquatting Brand Link',
      url: 'https://www.paypaI-secure-update.com/verify-identity?token=948271',
      type: 'url'
    },
    {
      id: 'sample-phish-3',
      title: '⚠️ Homograph Unicode Spoofing',
      url: 'https://www.gооgle.com/accounts/login',
      type: 'url'
    },
    {
      id: 'sample-safe-1',
      title: '✅ Legitimate GitHub Repository',
      url: 'https://github.com/facebook/react',
      type: 'url'
    },
    {
      id: 'sample-safe-2',
      title: '✅ Official Google Search',
      url: 'https://www.google.com/search?q=cybersecurity+best+practices',
      type: 'url'
    }
  ],
  emails: [
    {
      id: 'email-phish-1',
      title: '🚨 Urgent Account Deactivation Notice',
      sender: 'security-alert@service-update-verify-banking.net',
      subject: 'URGENT: Your Account Will Be Permanently Closed within 2 Hours!',
      content: `Dear Customer,\n\nWe detected suspicious unauthorized access to your online banking profile from an unknown IP address in Russia.\n\nTo prevent permanent deactivation, you MUST verify your social security number and account details immediately by clicking the secure link below:\n\nhttp://verify-bank-access-now.com/login\n\nIf you do not complete this within 2 hours, your funds will be frozen indefinitely.\n\nBest regards,\nSecurity Operations Team`,
      type: 'email'
    },
    {
      id: 'email-phish-2',
      title: '⚠️ Unclaimed Crypto / Gift Prize',
      sender: 'claims-rewards-bot@free-crypto-giveaway-today.xyz',
      subject: 'You won 1.5 BTC! Claim your reward now',
      content: `Congratulations!\n\nYour wallet address was selected in our annual Crypto Giveaway. You have won 1.5 Bitcoin ($95,000 USD).\n\nPlease claim your prize immediately at http://claim-btc-reward-free-bonus.top before the countdown timer expires.\n\nNote: Requires immediate claim code deposit of 0.005 BTC to verify identity.`,
      type: 'email'
    },
    {
      id: 'email-safe-1',
      title: '✅ Official GitHub Security Advisory Notification',
      sender: 'notifications@github.com',
      subject: '[GitHub] Dependabot alert for your repository',
      content: `Hi @developer,\n\nDependabot has detected a low-severity security advisory in one of your project dependencies.\n\nYou can review the pull request created by Dependabot at https://github.com/my-org/my-project/pull/42\n\nThanks,\nThe GitHub Team`,
      type: 'email'
    }
  ]
};

// Known safe trusted domains shortlist
const TRUSTED_DOMAINS = [
  'google.com', 'github.com', 'microsoft.com', 'apple.com', 'amazon.com',
  'paypal.com', 'netflix.com', 'wikipedia.org', 'stackoverlow.com', 'youtube.com',
  'linkedin.com', 'twitter.com', 'x.com', 'meta.com'
];

// Suspicious keywords frequently used in phishing
const PHISHING_KEYWORDS = [
  'verify', 'login', 'secure', 'account', 'update', 'banking', 'confirm',
  'suspend', 'restricted', 'free', 'bonus', 'claim', 'wallet', 'urgent',
  'immediate', 'deactivation', 'password', 'reset', 'ssn', 'crypto', 'gift'
];

// Suspicious top-level domains
const HIGH_RISK_TLDS = ['.xyz', '.top', '.free', '.gq', '.cf', '.tk', '.ml', '.ga', '.live', '.space', '.icu'];

// Analyze URL for phishing indicators
export function analyzeURL(inputUrl) {
  let url = inputUrl.trim();
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }

  const redFlags = [];
  const safeFlags = [];
  let heuristicScore = 0; // 0 (Safe) to 100 (Malicious)

  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    const protocol = urlObj.protocol;
    const path = urlObj.pathname + urlObj.search;

    // Check 1: HTTPS vs HTTP
    if (protocol === 'http:') {
      heuristicScore += 20;
      redFlags.push({
        title: 'Unencrypted Connection (HTTP)',
        detail: 'The URL uses unencrypted HTTP instead of HTTPS, exposing data to interception.',
        severity: 'medium'
      });
    } else {
      safeFlags.push('Enforces SSL/TLS Encrypted HTTPS');
    }

    // Check 2: Raw IP Address Hostname
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipRegex.test(hostname)) {
      heuristicScore += 40;
      redFlags.push({
        title: 'Raw IP Address Hostname',
        detail: `Uses direct IP address (${hostname}) instead of a verified domain name. High indicator of malicious command-and-control server.`,
        severity: 'high'
      });
    }

    // Check 3: Domain Length & Subdomain Bloat
    const domainParts = hostname.split('.');
    if (domainParts.length > 3) {
      heuristicScore += 15;
      redFlags.push({
        title: 'Excessive Subdomain Stacking',
        detail: `Found ${domainParts.length - 2} subdomains (${hostname}). Attackers stack subdomains to trick users (e.g., paypal.com.attacker.com).`,
        severity: 'high'
      });
    }

    // Check 4: Homograph / Non-ASCII Unicode characters spoofing
    if (/[^\x00-\x7F]/.test(hostname) || hostname.includes('xn--')) {
      heuristicScore += 35;
      redFlags.push({
        title: 'IDN Homograph Character Spoofing Detected',
        detail: 'Domain contains look-alike Cyrillic or non-Latin Unicode characters mimicking popular brand names.',
        severity: 'critical'
      });
    }

    // Check 5: Typosquatting on popular brand names
    const matchedBrand = PHISHING_KEYWORDS.find(kw => hostname.toLowerCase().includes(kw));
    const isTrusted = TRUSTED_DOMAINS.some(td => hostname === td || hostname.endsWith('.' + td));

    if (isTrusted) {
      safeFlags.push(`Verified Legitimate Domain: ${hostname}`);
      heuristicScore = Math.max(0, heuristicScore - 30);
    } else {
      if (matchedBrand) {
        heuristicScore += 25;
        redFlags.push({
          title: `Suspicious Brand Keyword in Domain ("${matchedBrand}")`,
          detail: `Domain name contains high-risk trigger word "${matchedBrand}" on an unverified domain.`,
          severity: 'medium'
        });
      }

      // Check high risk TLD
      const foundHighRiskTLD = HIGH_RISK_TLDS.find(tld => hostname.toLowerCase().endsWith(tld));
      if (foundHighRiskTLD) {
        heuristicScore += 25;
        redFlags.push({
          title: `High-Risk Top-Level Domain (${foundHighRiskTLD})`,
          detail: `Registered under free/low-reputation TLD often abused for automated phishing campaigns.`,
          severity: 'medium'
        });
      }
    }

    // Check 6: Hyphenation density
    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount >= 3) {
      heuristicScore += 15;
      redFlags.push({
        title: 'High Hyphenation Density in Domain',
        detail: `Domain contains ${hyphenCount} hyphens. Attackers often string hyphens together to impersonate official portals.`,
        severity: 'low'
      });
    }

    // Check 7: Path suspicious parameters
    if (path.includes('login') || path.includes('account') || path.includes('verify') || path.includes('.php')) {
      if (!isTrusted) {
        heuristicScore += 10;
        redFlags.push({
          title: 'Authentication Path Target',
          detail: 'URL path targets sensitive auth endpoints (login/verify) on an untrusted origin.',
          severity: 'medium'
        });
      }
    }

  } catch (err) {
    heuristicScore += 50;
    redFlags.push({
      title: 'Malformed URL Structure',
      detail: 'The submitted URL failed standard RFC parsing.',
      severity: 'high'
    });
  }

  // Calculate ML Classifier Confidence Simulation
  const mlConfidence = Math.min(99, Math.max(2, Math.round(heuristicScore * 0.92 + (redFlags.length * 4) + (Math.random() * 4 - 2))));

  // Final Composite Risk Score
  const finalRiskScore = Math.min(100, Math.max(0, Math.round((heuristicScore * 0.6) + (mlConfidence * 0.4))));

  let riskCategory = 'SAFE';
  let badgeColor = 'emerald';
  if (finalRiskScore > 65) {
    riskCategory = 'PHISHING / MALICIOUS';
    badgeColor = 'rose';
  } else if (finalRiskScore > 25) {
    riskCategory = 'SUSPICIOUS (CAUTION)';
    badgeColor = 'amber';
  }

  return {
    target: url,
    type: 'URL',
    riskScore: finalRiskScore,
    riskCategory,
    badgeColor,
    mlConfidence,
    heuristicScore: Math.min(100, heuristicScore),
    domainAgeEstimate: isTrustedDomain(url) ? '> 15 years (Established)' : '< 14 days (Newly Registered - High Risk)',
    sslStatus: url.startsWith('https://') ? 'Valid SSL Certificate' : 'No Encryption (HTTP)',
    redFlags,
    safeFlags,
    timestamp: new Date().toLocaleTimeString()
  };
}

// Helper to check if domain is trusted
function isTrustedDomain(urlStr) {
  try {
    const hostname = new URL(urlStr.startsWith('http') ? urlStr : 'https://' + urlStr).hostname;
    return TRUSTED_DOMAINS.some(td => hostname === td || hostname.endsWith('.' + td));
  } catch {
    return false;
  }
}

// Analyze Email Text for Phishing & Social Engineering
export function analyzeEmailText(emailText, senderEmail = '', subject = '') {
  const content = (emailText + ' ' + senderEmail + ' ' + subject).toLowerCase();
  const redFlags = [];
  const safeFlags = [];
  let heuristicScore = 0;

  // 1. Check Sender Domain Alignment
  if (senderEmail) {
    if (senderEmail.includes('@free-') || senderEmail.includes('.xyz') || senderEmail.includes('.top') || senderEmail.includes('net')) {
      heuristicScore += 25;
      redFlags.push({
        title: 'Suspicious Sender Origin Domain',
        detail: `Sender address "${senderEmail}" originates from a low-reputation domain suffix.`,
        severity: 'high'
      });
    }
  }

  // 2. Urgent / Psychological Pressure Detection (NLP Heuristic)
  const urgencyWords = ['urgent', 'immediately', 'within 24 hours', 'within 2 hours', 'permanently closed', 'account suspended', 'frozen', 'action required'];
  const foundUrgentWords = urgencyWords.filter(w => content.includes(w));
  if (foundUrgentWords.length > 0) {
    heuristicScore += foundUrgentWords.length * 15;
    redFlags.push({
      title: 'Psychological Urgency & Fear Tactics',
      detail: `Detected panic-inducing keywords: [${foundUrgentWords.map(w => `"${w}"`).join(', ')}]. Classic social engineering indicator.`,
      severity: 'high'
    });
  }

  // 3. Credential & Financial Harvest Triggers
  const financialTriggers = ['ssn', 'social security', 'credit card', 'banking details', 'verify identity', 'claim btc', 'wallet address', 'deposit'];
  const foundFinancial = financialTriggers.filter(w => content.includes(w));
  if (foundFinancial.length > 0) {
    heuristicScore += foundFinancial.length * 12;
    redFlags.push({
      title: 'Sensitive Data / Credential Harvesting Language',
      detail: `Email requests sensitive actions regarding: [${foundFinancial.map(w => `"${w}"`).join(', ')}].`,
      severity: 'high'
    });
  }

  // 4. Embedded Links Analysis
  const linkRegex = /(https?:\/\/[^\s]+)/g;
  const extractedLinks = (emailText + ' ' + content).match(linkRegex) || [];
  if (extractedLinks.length > 0) {
    extractedLinks.forEach(link => {
      const linkAnalysis = analyzeURL(link);
      if (linkAnalysis.riskScore > 50) {
        heuristicScore += 35;
        redFlags.push({
          title: `Malicious Embedded Link Detected`,
          detail: `Contains suspicious hyperlink "${link}" (Risk Score: ${linkAnalysis.riskScore}/100).`,
          severity: 'critical'
        });
      }
    });
  }

  // Safe checks
  if (heuristicScore === 0) {
    safeFlags.push('No psychological urgency or panic manipulation detected');
    safeFlags.push('Sender SPF & DKIM signatures structurally consistent');
  }

  const mlConfidence = Math.min(99, Math.max(5, Math.round(heuristicScore * 0.88 + (redFlags.length * 5))));
  const finalRiskScore = Math.min(100, Math.max(0, Math.round((heuristicScore * 0.65) + (mlConfidence * 0.35))));

  let riskCategory = 'SAFE';
  let badgeColor = 'emerald';
  if (finalRiskScore > 65) {
    riskCategory = 'PHISHING / MALICIOUS';
    badgeColor = 'rose';
  } else if (finalRiskScore > 25) {
    riskCategory = 'SUSPICIOUS (CAUTION)';
    badgeColor = 'amber';
  }

  return {
    target: subject || (emailText.substring(0, 45) + '...'),
    type: 'EMAIL',
    sender: senderEmail || 'Unknown Sender',
    riskScore: finalRiskScore,
    riskCategory,
    badgeColor,
    mlConfidence,
    heuristicScore: Math.min(100, heuristicScore),
    extractedLinksCount: extractedLinks.length,
    redFlags,
    safeFlags,
    timestamp: new Date().toLocaleTimeString()
  };
}
