# NECROS X — Autonomous Zombie API Detection & Defense System

> **A Banking API Immune System**  
> AI‑powered discovery, lifecycle classification, risk forecasting, attack‑path visualisation, honeypot defense, and hardware appliance readiness — all in a single deployable platform.

---

## 🏦 Problem Statement

Banks accumulate hundreds of undocumented, unmanaged APIs across legacy systems, shadow IT, and deprecated integrations. These "Zombie APIs" are invisible to security teams but remain accessible, becoming high‑value attack surfaces.

- **83 %** of organisations contain zombie APIs (Gartner)
- Average breach cost: **$4.45M**
- Traditional tools lack lifecycle visibility and cannot predict future risks.

NECROS X acts as an autonomous immune system that discovers, classifies, predicts, and defends the entire API surface — with a physical hardware appliance option for air‑gapped banking environments.

---

## 🚀 Features

| Module | Description |
|--------|-------------|
| **API Discovery Engine** | Simulated passive scanning of banking endpoints (ready to plug into real packet capture on Raspberry Pi) |
| **ML Lifecycle Classifier** | Real GradientBoosting model (scikit‑learn) trained on synthetic data — classifies APIs as `active`, `deprecated`, `orphaned`, or `zombie` |
| **Risk Scoring & Forecasting** | 0‑100 risk score + 30/60/90‑day forecast for every API |
| **Attack Path Visualisation** | Force‑directed graph (NetworkX + react‑force‑graph) showing API → database attack paths |
| **Honeypot Conversion** | High‑risk zombie APIs are converted into defensive honeypots with simulated attacker interactions |
| **Auto‑Defense Engine** | One‑click isolation of zombie APIs, simulated firewall deployment, and threat reduction |
| **AI Security Analyst** | GPT‑4o powered Q&A (fallback offline responses if no API key) |
| **Executive Dashboard** | Real‑time charts, PDF reports, voice alerts, keyboard shortcuts, terminal |
| **Appliance Mode** | Toggle to simulate the physical NECROS X Appliance (Raspberry Pi 5) with GPIO, packet stream, and hardware metrics |
| **Offline Resilient** | Frontend works with cached data; AI has offline fallback |

---

## 🧠 Machine Learning

- **Algorithm**: `GradientBoostingClassifier` (150 estimators, max_depth=5)
- **Features**: endpoint age, authentication status, response latency, error frequency, inactivity score, deprecated version flag, public exposure level, sensitive data access score
- **Training**: 500 synthetic banking API records generated on startup
- **Prediction**: lifecycle class, zombie probability, confidence, risk score
- **Forecast**: heuristic risk progression over 30/60/90 days based on feature trends

---

## 🛠 Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | React 18, Vite, Recharts, react‑force‑graph‑2d, jsPDF, Tailwind CSS (CDN) |
| Backend | FastAPI (Python), TinyDB, scikit‑learn, NetworkX, OpenAI API |
| Deployment | Netlify (frontend), Render (backend) — or unified single service |

---

