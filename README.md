# Capybank (Flask + SQLAlchemy + PostgreSQL)
Run locally: `pip install -r requirements.txt && python app.py` (uses SQLite unless DATABASE_URL is set).
Default admin: username `admin`, password `Admin#2026` (set ADMIN_USERNAME / ADMIN_PIN in env for production).

## Deploy to Render
1. Push this folder to a GitHub repo.
2. Render > New > Blueprint > pick the repo (uses render.yaml: web service + free Postgres). Set ADMIN_PIN when asked.
3. Or manually: New Postgres (free), then New Web Service: build `pip install -r requirements.txt`, start `gunicorn app:app`, env vars from .env.example (DATABASE_URL = Postgres Internal URL).
