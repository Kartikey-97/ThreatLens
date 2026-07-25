# ThreatLens

ThreatLens is an advanced, dual-layer AI and heuristic threat detection system. It provides real-time risk scoring for URLs and raw emails to detect phishing, malicious indicators, and brand impersonation.

## Architecture

ThreatLens is composed of a FastAPI backend and a React/Vite frontend.

### 1. The Machine Learning Engine
- URL Model: XGBoost classifier trained on domain structures.
- Email Model: LightGBM classifier with TF-IDF vectorization for text analysis.
- The models provide an initial statistical probability of a threat.

### 2. The Heuristic Engine
- A deterministic rule-based engine that acts as a failsafe against ML hallucinations.
- Features Levenshtein distance calculations against 300+ global brands for typosquatting detection.
- Overrides base ML scores when definitive safe or critical signals are identified.

### 3. Asynchronous OSINT Scraper
- Automatically checks domain age, SSL validity, and threat intelligence feeds.
- Fails open with a timeout: if the scraper fails or takes too long, the system degrades gracefully and relies purely on the ML and Heuristic models without hanging the user interface.

### 4. Generative AI Explainer
- Uses Google Gemini API to generate concise, human-readable explanations of why a specific target was flagged based on the underlying evidence.

## Project Structure

- /backend - FastAPI server, ML models integration, and heuristic logic.
- /frontend - React/Vite web application featuring a glassmorphic UI, dynamic SVGs, and local storage search history.
- /models - Pre-trained XGBoost and LightGBM models (.pkl files).
- /credibility_checker - The OSINT scraper module.

## Deployment Instructions

### Local Development

#### Backend
1. cd backend
2. python -m venv .venv
3. source .venv/bin/activate
4. pip install -r requirements.txt
5. Create a .env file and add: GEMINI_API_KEY=your_key_here
6. uvicorn main:app --host 0.0.0.0 --port 8000

#### Frontend
1. cd frontend
2. npm install
3. npm run dev

### Vercel Deployment
- Frontend: Drag and drop the /frontend folder into Vercel (zero config).
- Backend: Drag and drop the /backend folder into Vercel. A vercel.json is included for serverless deployment. Ensure you add GEMINI_API_KEY to your Vercel Environment Variables.
