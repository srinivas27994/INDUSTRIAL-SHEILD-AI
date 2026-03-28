# ⚡ IndustrialShield AI — ICS Cybersecurity Monitor v3.0

> **AI-powered anomaly detection for Industrial Control Systems (ICS/SCADA)**  
> Built for the AI Industrial Safety Hackathon

![Status](https://img.shields.io/badge/status-hackathon--ready-00ff9d)
![ML](https://img.shields.io/badge/ML-Isolation%20Forest-00c8ff)
![AI](https://img.shields.io/badge/AI-Offline%20%2B%20Claude-blueviolet)
![License](https://img.shields.io/badge/license-MIT-green)

---

## 🎯 What Is This?

IndustrialShield AI monitors industrial machine sensors **(temperature, pressure, vibration)** in real-time, detects anomalies using Machine Learning, and provides AI-powered explanations and recommendations to operators — even with zero internet connection.

### Real-World Problem It Solves
- Factories and plants run 24/7 — manual monitoring is impossible
- Equipment failures cause millions in damage and risk lives
- Cyberattacks on ICS (like Stuxnet) manipulate sensor data silently
- This system catches both **mechanical failures** and **cyber-physical attacks** early

---

## 🚀 Quick Start (60 seconds)

### Option 1 — Frontend Only (Zero Setup)
```
1. Download index.html
2. Double-click to open in any browser
3. Login: admin / admin123
4. Done ✅
```

### Option 2 — Full Stack (Frontend + Backend)
```bash
# Backend
cd backend/
pip install -r requirements.txt
python app.py
# Runs at http://localhost:5000

# Frontend
# Open index.html in browser — auto-connects to backend
```

---

## 🔐 Demo Credentials

| Role     | Username   | Password   | Access          |
|----------|------------|------------|-----------------|
| Admin    | `admin`    | `admin123` | Full access + retrain model |
| Operator | `operator` | `op123`    | Monitor + view  |

---

## 📁 Project Structure

```
IndustrialShield-AI/
├── index.html          ← Complete frontend (single file, self-contained)
├── README.md           ← This file
└── backend/
    ├── app.py          ← Flask REST API (12 endpoints)
    └── requirements.txt
```

---

## 🧠 How It Works

```
Sensor Data → Isolation Forest ML → Anomaly Score → Alert + Explanation → AI Chatbot
     ↓                                                        ↓
[Temp/Press/Vib]    [Unsupervised Learning]           [Rule Engine + Claude API]
```

### ML Algorithm — Isolation Forest
- **Unsupervised** — no labeled data needed
- Trained on 600 normal operating baseline readings
- Detects subtle **multi-variate anomalies** (e.g., temp + vibration together abnormal)
- Outputs a **confidence score** (0–100%)
- Supports **continuous learning** — retrain with real historical data

### Normal Operating Ranges
| Sensor      | Safe Range    | Warning     | Critical    |
|-------------|---------------|-------------|-------------|
| Temperature | 60°C – 85°C   | > 85°C      | > 95°C      |
| Pressure    | 2.5 – 5.5 bar | > 5.5 bar   | > 6.0 bar   |
| Vibration   | 0.1 – 2.5 mm/s| > 2.5 mm/s  | > 3.0 mm/s  |

---

## 🌐 API Endpoints (Backend)

| Method | Endpoint            | Auth     | Description              |
|--------|---------------------|----------|--------------------------|
| GET    | `/health`           | ❌        | System health check      |
| POST   | `/auth/login`       | ❌        | Login                    |
| POST   | `/auth/register`    | ❌        | Register user            |
| POST   | `/predict`          | ✅        | Anomaly detection        |
| POST   | `/predict/batch`    | ✅        | Batch analysis (100 max) |
| GET    | `/history`          | ✅        | Fetch prediction logs    |
| GET    | `/history/export`   | ✅        | Download CSV             |
| GET    | `/history/stats`    | ✅        | Aggregated statistics    |
| GET    | `/alerts`           | ✅        | Alert log                |
| POST   | `/retrain`          | 🔐 Admin  | Retrain ML model         |
| GET    | `/model/info`       | ✅        | Model details            |
| GET    | `/users`            | 🔐 Admin  | User list                |

### Example API Calls
```bash
# Login
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# Predict anomaly
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer admin:admin123" \
  -d '{"temperature":98.5,"pressure":6.2,"vibration":3.1}'

# Get stats
curl http://localhost:5000/history/stats \
  -H "Authorization: Bearer admin:admin123"
```

---

## 🎮 Features

### Dashboard
- ▶ Start / ⏹ Stop simulation
- 3 simulation modes: **Normal** / **Random** (25% anomaly) / **Anomaly** (forced)
- Adjustable interval: 1s / 2s / 3s / 5s
- Live sensor cards with animated status
- Real-time Chart.js line graph (last 30 readings)
- AI analysis panel with root cause + recommendations
- Export **CSV** and **PDF Report**

### AI Chatbot (Works Offline — No API Key Needed)
Answers these questions with real sensor data context:
- "Why is this abnormal?"
- "What should I do?"
- "Analyze recent trends"
- "Is this a cyberattack?"
- "Explain Isolation Forest"
- "Generate maintenance report"

**Optional Claude AI upgrade** — paste your Anthropic API key for full AI intelligence

### Analytics Page
- Doughnut chart (Safe / Warning / Critical distribution)
- Average sensor values with progress bars
- Safe rate percentage
- Session statistics

### Alerts Log
- Full history of all anomaly events
- Filter by: All / Critical / Warning
- Clear all alerts

### Admin Panel *(Admin role only)*
- ML model info and status
- One-click model retrain with historical data
- User management table

---

## ☁️ Deployment

### Frontend → Netlify (Free)
```
1. Go to netlify.com/drop
2. Drag and drop index.html
3. Done — live URL in 30 seconds ✅
```

### Frontend → Vercel (Free)
```bash
npm i -g vercel
vercel --prod
```

### Backend → Railway (Free tier)
```bash
# Add railway.toml in backend/
cat > railway.toml << EOF
[build]
builder = "nixpacks"
[deploy]
startCommand = "gunicorn app:app --bind 0.0.0.0:$PORT"
EOF

railway login && railway init && railway up
```

### Backend → Render (Free tier)
1. Connect GitHub at render.com
2. Root Directory: `backend/`
3. Build: `pip install -r requirements.txt`
4. Start: `gunicorn app:app`

### Docker
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install -r requirements.txt
COPY backend/ .
EXPOSE 5000
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:5000", "--workers", "4"]
```

---

## 🏆 Tech Stack

| Layer      | Technology                            |
|------------|---------------------------------------|
| Frontend   | React 18, Chart.js 4, CSS3           |
| ML Engine  | Isolation Forest (pure JavaScript)    |
| AI Chatbot | Offline rule engine + Claude API      |
| Backend    | Flask 3.0, Flask-CORS                 |
| Database   | SQLite (localStorage in browser mode) |
| Auth       | Role-based Bearer token auth          |
| Alerts     | Web Audio API (sound) + visual toasts |
| Fonts      | Orbitron, JetBrains Mono, Rajdhani    |
| Deploy     | Netlify / Vercel + Railway / Render   |

---

## ✅ Full Features Checklist

| Feature                          | Status    |
|----------------------------------|-----------|
| Isolation Forest anomaly detection | ✅ Done  |
| Confidence scoring               | ✅ Done   |
| Real-time sensor simulation      | ✅ Done   |
| Live Chart.js visualization      | ✅ Done   |
| AI chatbot (offline + Claude)    | ✅ Done   |
| Sound alerts (Web Audio API)     | ✅ Done   |
| Color-coded warnings (🟢🟡🔴)   | ✅ Done   |
| Historical data table            | ✅ Done   |
| CSV export                       | ✅ Done   |
| PDF report export                | ✅ Done   |
| Role-based auth (Admin/Operator) | ✅ Done   |
| Anomaly explanation system       | ✅ Done   |
| Continuous learning / retrain    | ✅ Done   |
| Analytics page                   | ✅ Done   |
| Alerts log with filtering        | ✅ Done   |
| Admin panel                      | ✅ Done   |
| Toast notifications              | ✅ Done   |
| Dark glassmorphism UI            | ✅ Done   |
| Mobile responsive                | ✅ Done   |
| Landing page                     | ✅ Done   |
| About / project info page        | ✅ Done   |
| Flask REST API backend           | ✅ Done   |
| Batch prediction endpoint        | ✅ Done   |
| SQLite database                  | ✅ Done   |
| Deployment guide                 | ✅ Done   |

---

## 👥 Team

Built for the **AI Industrial Safety Hackathon**

*IndustrialShield AI v3.0 — Protecting Critical Infrastructure with Machine Learning*
