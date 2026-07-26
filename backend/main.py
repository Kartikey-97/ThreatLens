"""
ThreatLens — FastAPI Backend

Unified risk-scoring API that integrates:
  • ML models (XGBoost URL classifier + LightGBM email classifier)
  • Heuristic engine (structural URL rules + email content rules)
  • Homoglyph / typosquat detection
  • Web scraper (optional, with timeout-based graceful degradation)

Endpoints:
  POST /check-url   — analyze a URL for phishing / malicious indicators
  POST /check-email  — analyze email text for phishing indicators
  GET  /health       — service health check
"""

from __future__ import annotations

import logging
import os
import joblib
import sys
import time
import asyncio
import requests
from contextlib import asynccontextmanager
from typing import Any, Optional
from google import genai
from dotenv import load_dotenv

import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger("threatlens")

# Load environment variables
load_dotenv()

# Configure Gemini
api_key = os.getenv("GEMINI_API_KEY")
if not api_key:
    logger.warning("GEMINI_API_KEY not found in environment variables. LLM explanations will be disabled.")
else:
    # Initialize a global client
    _genai_client = genai.Client(api_key=api_key)

# ---------------------------------------------------------------------------
# Ensure backend/ is on sys.path so sibling modules import cleanly
# ---------------------------------------------------------------------------
_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

# ---------------------------------------------------------------------------
# Internal module imports  (deferred until after sys.path setup)
# ---------------------------------------------------------------------------
from models import Finding, RiskResult, Severity
from risk_engine import compute_final_risk
from scraper_client import get_scraper_report
from feature_extraction.url_features import extract_url_features
from feature_extraction.email_features import extract_email_features
from heuristic_engine.homoglyph import load_brand_domains, check_homoglyph, check_email_domain_lookalike
from heuristic_engine.url_heuristics import run_url_heuristics, collect_safe_signals
from heuristic_engine.email_heuristics import run_email_heuristics, collect_email_safe_signals

# ---------------------------------------------------------------------------
# Paths to model artifacts
# ---------------------------------------------------------------------------
_MODELS_DIR = os.path.join(os.path.dirname(_BACKEND_DIR), "models")
_DATA_DIR = os.path.join(_BACKEND_DIR, "data")


# ═══════════════════════════════════════════════════════════════════════════
# Pydantic request / response schemas
# ═══════════════════════════════════════════════════════════════════════════

class URLRequest(BaseModel):
    url: str = Field(..., min_length=1, description="The URL to analyze")


class EmailRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Raw email body text")
    sender: str = Field(default="", description="Sender email address")
    subject: str = Field(default="", description="Email subject line")
    headers: dict[str, str] | None = Field(
        default=None,
        description="Optional raw email headers (e.g. From, Reply-To, Authentication-Results)",
    )


class EvidenceItem(BaseModel):
    severity: str
    finding: str


class RiskResponse(BaseModel):
    risk_score: int = Field(..., ge=0, le=100)
    classification: str
    ml_probability: float
    evidence: list[EvidenceItem]
    recommendation: str
    safe_signals: list[str] = []
    llm_explanation: str | None = None


class HealthResponse(BaseModel):
    status: str
    models_loaded: bool
    brand_domains_count: int


# ═══════════════════════════════════════════════════════════════════════════
# Application state — loaded once at startup
# ═══════════════════════════════════════════════════════════════════════════

class AppState:
    """Container for all artifacts loaded at startup."""

    url_model: Any = None
    url_feature_names: list[str] = []
    url_importances: Any = None

    email_model: Any = None
    email_tfidf: Any = None
    email_feature_names: list[str] = []
    email_importances: Any = None

    brand_domains: list[dict] = []

    models_loaded: bool = False


_state = AppState()


def _load_pickle(path: str, description: str) -> Any:
    """Load a pickle file with error logging."""
    try:
        obj = joblib.load(path)
        logger.info("Loaded %s from %s", description, os.path.basename(path))
        return obj
    except Exception:
        logger.exception("Failed to load %s from %s", description, path)
        return None


def _load_all_artifacts() -> None:
    """Load every model artifact and the brand domain list into _state."""

    # ── URL model artifacts ─────────────────────────────────────────────
    _state.url_model = _load_pickle(
        os.path.join(_MODELS_DIR, "url_model.pkl"), "URL XGBoost model"
    )
    features = _load_pickle(
        os.path.join(_MODELS_DIR, "url_model_features.pkl"), "URL feature names"
    )
    _state.url_feature_names = features if features else []

    _state.url_importances = _load_pickle(
        os.path.join(_MODELS_DIR, "url_model_importances.pkl"), "URL feature importances"
    )

    # ── Email model artifacts ───────────────────────────────────────────
    _state.email_model = _load_pickle(
        os.path.join(_MODELS_DIR, "email_model.pkl"), "Email LightGBM model"
    )
    _state.email_tfidf = _load_pickle(
        os.path.join(_MODELS_DIR, "email_tfidf_vectorizer.pkl"), "Email TF-IDF vectorizer"
    )
    eng_features = _load_pickle(
        os.path.join(_MODELS_DIR, "email_engineered_features.pkl"),
        "Email engineered feature names",
    )
    _state.email_feature_names = eng_features if eng_features else []

    _state.email_importances = _load_pickle(
        os.path.join(_MODELS_DIR, "email_model_importances.pkl"),
        "Email feature importances",
    )

    # ── Brand domains ───────────────────────────────────────────────────
    brand_path = os.path.join(_DATA_DIR, "brand_domains.json")
    try:
        _state.brand_domains = load_brand_domains(brand_path)
        logger.info("Loaded %d brand domains", len(_state.brand_domains))
    except Exception:
        logger.exception("Failed to load brand domains from %s", brand_path)
        _state.brand_domains = []

    # ── Summary ─────────────────────────────────────────────────────────
    _state.models_loaded = (
        _state.url_model is not None
        and _state.email_model is not None
        and _state.email_tfidf is not None
    )
    if _state.models_loaded:
        logger.info("All ML models loaded successfully")
    else:
        logger.warning("Some ML models failed to load — predictions will degrade")


# ═══════════════════════════════════════════════════════════════════════════
# Lifespan (startup / shutdown)
# ═══════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load all artifacts at startup, clean up at shutdown."""
    logger.info("Starting ThreatLens backend — loading artifacts...")
    _load_all_artifacts()
    yield
    logger.info("ThreatLens backend shutting down")


# ═══════════════════════════════════════════════════════════════════════════
# FastAPI app
# ═══════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="ThreatLens API",
    description="Phishing & Malicious URL/Email Detector — Risk Scoring API",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow the Vite dev server and common local dev origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "*",  # fallback for demo flexibility
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ═══════════════════════════════════════════════════════════════════════════
# Helper: ML prediction with error handling
# ═══════════════════════════════════════════════════════════════════════════

def _predict_url_ml(url: str) -> float:
    """Run the URL ML model and return phishing probability (0.0 – 1.0).

    Returns 0.5 (uncertain) if the model isn't loaded or extraction fails.
    """
    if _state.url_model is None:
        logger.warning("URL model not loaded — returning 0.5 default")
        return 0.5

    try:
        features = extract_url_features(url, _state.brand_domains)
        features_array = np.array([features], dtype=np.float64)
        prob = float(_state.url_model.predict_proba(features_array)[0, 1])
        return prob
    except Exception:
        logger.exception("URL ML prediction failed for %s", url)
        return 0.5


def _predict_email_ml(text: str) -> float:
    """Run the email ML model and return phishing probability (0.0 – 1.0).

    Returns 0.5 (uncertain) if the model isn't loaded or extraction fails.
    """
    if _state.email_model is None or _state.email_tfidf is None:
        logger.warning("Email model not loaded — returning 0.5 default")
        return 0.5

    try:
        feature_matrix = extract_email_features(text, _state.email_tfidf)
        prob = float(_state.email_model.predict_proba(feature_matrix)[0, 1])
        return prob
    except Exception:
        logger.exception("Email ML prediction failed")
        return 0.5


async def _generate_llm_explanation(result: RiskResult, target: str, scan_type: str, raw_html: str | None = None, raw_email: str | None = None) -> str | None:
    """Uses Gemini to generate a short, human-readable explanation of the threat."""
    if not os.getenv("GEMINI_API_KEY"):
        return "Error: GEMINI_API_KEY is not set in the environment variables."
        
    if '_genai_client' not in globals():
        return "Error: Gemini Client was not initialized properly."
        
    try:
        # Build a prompt based on the evidence
        evidence_text = "\n".join([f"- [{str(e.get('severity', 'info')).upper()}] {e.get('finding', '')}" for e in result.evidence])
        
        deep_scan_context = ""
        if raw_html:
            deep_scan_context = f"\nRaw Target HTML Source Snippet:\n```html\n{raw_html[:3000]}\n```\nAnalyze the HTML for phishing forms, hidden fields, or deceptive code.\n"
        if raw_email:
            deep_scan_context = f"\nRaw Email Text:\n```\n{raw_email[:3000]}\n```\nAnalyze the email text for social engineering, false urgency, or manipulation tactics.\n"
            
        prompt = f"""
        You are a ThreatLens security analyzer. Your job is to provide a brief, objective, and professional summary of this threat scan.
        Target: {target}
        Scan Type: {scan_type}
        Risk Score: {result.risk_score}/100
        Classification: {result.classification.upper()}
        
        Raw Evidence:
        {evidence_text if evidence_text else "None"}
        {deep_scan_context}
        
        Task: Write a highly concise, 1-2 sentence explanation of the risk.
        Be objective and direct. Do NOT use dramatic language or adopt an over-the-top persona. 
        Simply state what the evidence indicates and why the risk score was assigned (e.g., "The URL is safe because it belongs to an established domain with a valid SSL certificate" or "This email is highly dangerous because the HTML contains a hidden credential harvesting form").
        """
        
        response = await asyncio.to_thread(
            _genai_client.models.generate_content,
            model='gemini-1.5-flash',
            contents=prompt,
        )
        return response.text.strip()
    except Exception as e:
        logger.exception("Failed to generate LLM explanation")
        return f"Google API Error: {str(e)}"


# ═══════════════════════════════════════════════════════════════════════════
# Endpoints
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/health", response_model=HealthResponse)
async def health():
    """Service health check."""
    return HealthResponse(
        status="ok" if _state.models_loaded else "degraded",
        models_loaded=_state.models_loaded,
        brand_domains_count=len(_state.brand_domains),
    )


@app.post("/check-url", response_model=RiskResponse)
async def check_url(req: URLRequest):
    """Analyze a URL for phishing / malicious indicators.

    Pipeline:
      1. ML model prediction (URL feature extraction → XGBoost)
      2. Heuristic engine (structural rules + homoglyph/typosquat)
      3. Optional scraper enrichment (domain age, SSL, safety status)
      4. Risk engine combines all → final score + explanation
    """
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    # Ensure URL has a scheme for consistent processing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    t0 = time.perf_counter()

    # ── 1. ML prediction ────────────────────────────────────────────────
    ml_prob = _predict_url_ml(url)
    logger.info("URL ML probability: %.4f for %s", ml_prob, url)

    # ── 2. Homoglyph / typosquat detection ──────────────────────────────
    homoglyph_findings = check_homoglyph(url, _state.brand_domains)

    # ── 3. Scraper (async, with timeout-based degradation) ──────────────
    scraper_data = None
    raw_html = None
    
    async def fetch_html(target_url: str) -> str | None:
        try:
            resp = await asyncio.to_thread(requests.get, target_url, timeout=3.0)
            return resp.text[:10000] if resp.status_code == 200 else None
        except Exception:
            return None

    try:
        scraper_task = asyncio.create_task(get_scraper_report(url, timeout=5.0))
        html_task = asyncio.create_task(fetch_html(url))
        scraper_data, raw_html = await asyncio.gather(scraper_task, html_task)
    except Exception:
        logger.warning("Scraper/HTML fetch failed for %s — proceeding without it", url)

    # ── 4. URL heuristic engine ─────────────────────────────────────────
    heuristic_findings = run_url_heuristics(url, homoglyph_findings, scraper_data)

    # ── 5. Safe signals ─────────────────────────────────────────────────
    safe_signals = collect_safe_signals(url, scraper_data)

    # ── 6. Risk engine ──────────────────────────────────────────────────
    result = compute_final_risk(
        ml_probability=ml_prob,
        findings=heuristic_findings,
        safe_signals=safe_signals,
        scan_type="url",
    )

    elapsed = time.perf_counter() - t0
    logger.info(
        "URL check complete: score=%d, class=%s, findings=%d, elapsed=%.3fs",
        result.risk_score, result.classification, len(heuristic_findings), elapsed,
    )
    
    # Generate LLM explanation
    llm_expl = await _generate_llm_explanation(result, url, "url", raw_html=raw_html)

    return RiskResponse(
        risk_score=result.risk_score,
        classification=result.classification,
        ml_probability=result.ml_probability,
        evidence=[EvidenceItem(**e) for e in result.evidence],
        recommendation=result.recommendation,
        safe_signals=result.safe_signals,
        llm_explanation=llm_expl,
    )


@app.post("/check-email", response_model=RiskResponse)
async def check_email(req: EmailRequest):
    """Analyze email text for phishing indicators.

    Pipeline:
      1. ML model prediction (TF-IDF + engineered features → LightGBM)
      2. Heuristic engine (header checks + content rules + sender-domain lookalike)
      3. Risk engine combines all → final score + explanation
    """
    text = req.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Email text cannot be empty")

    # Combine subject + body for ML input (matches training pipeline)
    full_text = ""
    if req.subject:
        full_text = req.subject + " "
    full_text += text

    t0 = time.perf_counter()

    # ── 1. ML prediction ────────────────────────────────────────────────
    ml_prob = _predict_email_ml(full_text)
    logger.info("Email ML probability: %.4f", ml_prob)

    # ── 2. Sender-domain homoglyph detection ────────────────────────────
    homoglyph_findings: list[Finding] = []
    if req.sender:
        homoglyph_findings = check_email_domain_lookalike(req.sender, _state.brand_domains)

    # ── 3. Email heuristic engine ───────────────────────────────────────
    heuristic_findings = run_email_heuristics(
        text=text,
        sender=req.sender,
        subject=req.subject,
        headers=req.headers,
        homoglyph_findings=homoglyph_findings,
    )

    # ── 4. Safe signals ─────────────────────────────────────────────────
    safe_signals = collect_email_safe_signals(text, req.sender, req.headers)

    # ── 5. Risk engine ──────────────────────────────────────────────────
    result = compute_final_risk(
        ml_probability=ml_prob,
        findings=heuristic_findings,
        safe_signals=safe_signals,
        scan_type="email",
    )

    elapsed = time.perf_counter() - t0
    logger.info(
        "Email check complete: score=%d, class=%s, findings=%d, elapsed=%.3fs",
        result.risk_score, result.classification, len(heuristic_findings), elapsed,
    )

    # Generate LLM explanation
    llm_expl = await _generate_llm_explanation(result, req.sender or "Email Content", "email", raw_email=full_text)

    return RiskResponse(
        risk_score=result.risk_score,
        classification=result.classification,
        ml_probability=result.ml_probability,
        evidence=[EvidenceItem(**e) for e in result.evidence],
        recommendation=result.recommendation,
        safe_signals=result.safe_signals,
        llm_explanation=llm_expl,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Direct execution
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
