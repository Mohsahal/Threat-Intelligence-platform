# 🛡️ Threat Intelligence Platform (TIP)

A production-ready Threat Intelligence Platform built with **Python 3.10+**, **MongoDB**, and **Flask**. It collects threat data from VirusTotal, normalises and stores it in MongoDB, scores indicators by severity, and exposes a REST API with alerts.

---

## 📁 Project Structure

```
threat-intelligence-platform/
│
├── app.py                  # Flask REST API (entry point)
├── collector.py            # Pipeline orchestrator
├── virustotal_client.py    # VirusTotal API wrapper (with retry logic)
├── normalizer.py           # Raw API response → clean document
├── scorer.py               # Threat scoring & alert generation
├── storage.py              # MongoDB CRUD helpers
├── database.py             # MongoDB connection manager
├── config.py               # Config loader (reads .env)
├── logger.py               # Centralised logging
│
├── test_platform.py        # Integration test / demo script
│
├── .env                    # Your environment variables (git-ignored)
├── .env.example            # Template – copy to .env
├── requirements.txt        # Python dependencies
├── logs/
│   └── tip.log             # Auto-created at runtime
└── README.md
```

---

## ⚡ Quick Start

### 1. Prerequisites

| Tool | Version |
|------|---------|
| Python | 3.10 or higher |
| MongoDB | 6.x running locally on port 27017 |
| VirusTotal Account | Free tier at [virustotal.com](https://www.virustotal.com/) |

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure environment

```bash
# Copy the example file
copy .env.example .env       # Windows
cp  .env.example .env        # Linux / macOS

# Open .env and replace YOUR_VIRUSTOTAL_API_KEY_HERE with your real key
```

### 4. Start MongoDB

Make sure MongoDB is running locally:

```bash
# Windows (if installed as a service)
net start MongoDB

# Or start mongod directly
mongod --dbpath "C:\data\db"
```

### 5. Start the Flask API

```bash
python app.py
```

You should see:

```
2026-04-14 20:00:00  [INFO    ]  ThreatIntelPlatform  →  Connecting to MongoDB at mongodb://localhost:27017/
2026-04-14 20:00:00  [INFO    ]  ThreatIntelPlatform  →  MongoDB connection successful.
2026-04-14 20:00:00  [INFO    ]  ThreatIntelPlatform  →  Starting Threat Intelligence Platform API on 0.0.0.0:5000
 * Running on http://0.0.0.0:5000
```

---

## 🌐 REST API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Liveness probe – checks API + MongoDB |
| `GET` | `/alerts` | List all alerts (optional `?severity=high`) |
| `GET` | `/threats` | List all stored threat indicators |
| `GET` | `/threats/<indicator>` | Fetch a single IP or domain |
| `POST` | `/collect` | Trigger a collection run |

### POST /collect – Request body

```json
{
  "indicators": ["8.8.8.8", "example.com", "185.220.101.45"]
}
```

### GET /alerts – Response example

```json
{
  "count": 2,
  "alerts": [
    {
      "indicator": "185.220.101.45",
      "indicator_type": "ip",
      "threat_score": 82,
      "severity": "high",
      "malicious_count": 18,
      "message": "[HIGH] Threat detected: 185.220.101.45 scored 82/100 on VirusTotal.",
      "triggered_at": "2026-04-14T15:00:00+00:00"
    }
  ]
}
```

---

## 🎯 Threat Scoring System

| Score Range | Severity | Alert Created? |
|-------------|----------|----------------|
| 0 – 29 | 🟢 Low | No |
| 30 – 69 | 🟡 Medium | Yes |
| 70 – 100 | 🔴 High | Yes |

Thresholds are configurable via `LOW_THRESHOLD` and `HIGH_THRESHOLD` in `.env`.

---

## 🧪 Running the Tests

> ⚠️ The Flask server must be running before running the test script.

```bash
# Terminal 1
python app.py

# Terminal 2
python test_platform.py
```

The test script exercises all 6 API endpoints and prints a summary.

---

## 🔄 Retry Logic

All VirusTotal API calls automatically retry up to `MAX_RETRIES` times with exponential back-off:

- **Network error** → retry
- **HTTP 429** (rate limit) → wait and retry
- **HTTP 5xx** → retry
- **HTTP 401 / 404** → fail immediately (no retry)

Configure `MAX_RETRIES` and `RETRY_DELAY` in `.env`.

---

## 📝 Logs

All events are logged to both the terminal and `logs/tip.log`.

```
logs/tip.log  ← persisted across runs
```

---

## 🔒 Security Notes

- Never commit your real `.env` file to version control
- `.env` is intentionally excluded from source by best-practice (add to `.gitignore`)
- The VirusTotal free tier allows **500 requests/day** (4 lookups/minute)
