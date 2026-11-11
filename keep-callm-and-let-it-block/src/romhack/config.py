"""Runtime settings. Defaults match compose.yml; environment variables override them."""
import os

DEFAULTS = {
    "db_path": "/data/workshop.db",
    "workflows_dir": "/workflows",
    "splunk_hec_url": "http://splunk:8088",
    "splunk_hec_token": "6f1c2a4e-9b7d-4c3e-8a5f-0e1d2c3b4a59",
    "splunk_api_url": "https://splunk:8089",
    "splunk_admin_password": "RomHack2026!",
    "splunk_analyst_user": "analyst",
    "splunk_analyst_password": "Analyst2026!",
    # Where the dispatcher delivers alerts, and the address your browser uses for n8n.
    "n8n_webhook_url": "http://n8n:5678/webhook/romhack",
    "n8n_public_url": "http://localhost:5678",
    "splunk_public_url": "http://localhost:8000",
    "target_public_url": "http://localhost:8081",
    # The simulated production website, served by this same process.
    "target_url": "http://127.0.0.1:8081",
    "realert_seconds": 120,
    "evidence_timeout_seconds": 180,
    "traffic_interval_seconds": 1.0,
    "traffic_requests_per_pass": 3,
    "production_interval_seconds": 5,
    "production_freshness_seconds": 20,
}


def load_config(environ=None):
    environ = os.environ if environ is None else environ
    config = dict(DEFAULTS)
    for key, default in DEFAULTS.items():
        raw = environ.get("ROMHACK_" + key.upper())
        if raw is not None:
            config[key] = type(default)(raw)
    if environ.get("SPLUNK_PASSWORD"):
        config["splunk_admin_password"] = environ["SPLUNK_PASSWORD"]
    return config
