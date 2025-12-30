# Honeypot Analyzer 🛡️🐝

A full-stack cybersecurity analysis platform for ingesting, processing, and visualizing honeypot logs. The system allows uploading logs or connecting directly to honeypots, enriches events with threat intelligence, and presents actionable insights via a modern dashboard.

---

## 📌 Features

* 📥 Upload honeypot log files (JSON-based)
* 🔌 Connect to live honeypots via API/connectors
* 🧠 Automated log parsing & enrichment
* 🕵️ Threat intelligence correlation
* 🧾 STIX object generation for CTI workflows
* 📊 Interactive dashboards & visualizations
* 🐳 Dockerized backend & frontend

---

## 🏗️ Project Architecture

```
honeypot-analyzer/
├── backend/        # FastAPI backend
├── frontend/       # React + Vite frontend
├── docker-compose.yml
├── README.md
└── .gitignore
```

The project follows a **clean, service-oriented architecture**:

* Backend: FastAPI (Python)
* Frontend: React (Vite)
* Communication: REST API (JSON)

---

## ⚙️ Backend Structure (FastAPI)

```
backend/app/
├── main.py              # FastAPI app entry point
├── api/                 # API routes & connectors
│   ├── endpoints.py
│   └── honeypot_connector.py
├── core/                # App configuration & security
│   ├── config.py
│   └── security.py
├── models/              # Schemas & DB setup
│   ├── schemas.py
│   └── database.py
├── services/            # Business logic
│   ├── log_processor.py
│   ├── threat_intelligence.py
│   └── stix_generator.py
├── utils/               # Helpers & file utilities
│   ├── file_handlers.py
│   └── helpers.py
```

### Key Responsibilities

* **Log Processing**: Normalize and parse honeypot logs
* **Threat Intelligence**: IP reputation, attack pattern detection
* **STIX Generation**: Produce structured CTI objects
* **Security**: Authentication & request validation

---

## 🎨 Frontend Structure (React + Vite)

```
frontend/src/
├── components/
│   ├── Dashboard/        # Overview & stats
│   ├── LogUpload/        # File upload UI
│   ├── HoneypotConnect/  # Live honeypot connection
│   ├── Analysis/         # Threat analysis views
│   └── Common/           # Shared UI components
├── services/             # API & auth services
├── App.jsx
├── index.js
└── index.css
```

### UI Highlights

* 📊 Stats cards & timelines
* 🌍 Attack map visualization
* 📁 Drag-and-drop file uploads
* 📋 Threat tables with enrichment data

---

## 🚀 Getting Started (Local Development)

### 1️⃣ Clone Repository

```bash
git clone https://github.com/gmulonga/honeypot.git
cd honeypot-analyzer
```

---

### 2️⃣ Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```


Run the backend:

```bash
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Backend will be available at:
👉 [http://localhost:8000](http://localhost:8000)

API Docs:
👉 [http://localhost:8000/docs](http://localhost:8000/docs)

---

### 3️⃣ Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

Frontend will be available at:
👉 [http://localhost:5173](http://localhost:5173)

---

## 🐳 Docker Setup (Optional)

Run everything with Docker:

```bash
docker-compose up --build
```

---

## 🔄 Typical Workflow

1. Upload honeypot logs **or** connect to a live honeypot
2. Backend parses and normalizes events
3. Threat intelligence enrichment is applied
4. STIX objects are generated
5. Results are visualized on the dashboard


---

## 🛠️ Tech Stack

**Backend**

* Python 3.9+
* FastAPI
* Pydantic
* Uvicorn

**Frontend**

* React
* Vite

**DevOps**

* Docker
* Docker Compose

