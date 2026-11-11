"""Workshop API (called by your n8n workflow) and the lab portal."""
import json
from importlib.resources import files
from pathlib import Path
from typing import Literal

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field, field_validator

from . import portal as portal_page
from . import production, progress, splunk
from .intel import lookup
from .runtime import PHASES, InvalidRequest, NotFound, Rejected

ASSETS = files("romhack").joinpath("assets")


class Action(BaseModel):
    action: str
    src_ip: str
    run_id: str
    idempotency_key: str
    ttl_seconds: int | None = None


class Phase(BaseModel):
    phase: Literal["Base", "A", "B", "C1", "C2", "C3"]


class Approval(BaseModel):
    url: str = Field(max_length=2048)
    run_id: str
    src_ip: str


AUDIT_REASONING_LIMIT = 4000
AUDIT_EVIDENCE_ITEMS = 20
AUDIT_EVIDENCE_LENGTH = 1000
AUDIT_TRUNCATED = " …[truncated]"


def clip(text, limit):
    """Model verdicts are unbounded; an audit is worth more clipped than rejected."""
    return text if len(text) <= limit else text[:limit - len(AUDIT_TRUNCATED)] + AUDIT_TRUNCATED


class Audit(BaseModel):
    run_id: str = Field(min_length=1, max_length=128)
    decision: str | bool
    src_ip: str = Field(default="", max_length=45)
    event_id: str = Field(default="", max_length=128)
    kind: str = Field(default="workflow", max_length=40)
    reasoning: str = Field(default="", max_length=AUDIT_REASONING_LIMIT)
    evidence: list[str] = Field(default_factory=list, max_length=AUDIT_EVIDENCE_ITEMS)

    @field_validator("reasoning", mode="before")
    @classmethod
    def clip_reasoning(cls, value):
        return clip(value, AUDIT_REASONING_LIMIT) if isinstance(value, str) else value

    @field_validator("evidence", mode="before")
    @classmethod
    def clip_evidence(cls, value):
        if not isinstance(value, list):
            return value
        items = [item if isinstance(item, str) else json.dumps(item, ensure_ascii=False) for item in value[:AUDIT_EVIDENCE_ITEMS]]
        return [clip(item, AUDIT_EVIDENCE_LENGTH) for item in items]


# What the search tool hands back to an agent: enough rows to reason over, small
# enough for any model's context. Larger results are cut, never refused.
SEARCH_ROWS = 50
SEARCH_BYTES = 40_000


def fit(rows):
    truncated = len(rows) > SEARCH_ROWS
    rows = rows[:SEARCH_ROWS]
    while rows and len(json.dumps(rows)) > SEARCH_BYTES:
        rows, truncated = rows[:len(rows) // 2], True
    return rows, truncated


class Search(BaseModel):
    search: str = Field(min_length=1, max_length=8000)
    run_id: str


def create_app(workshop, search=None):
    config, store = workshop.config, workshop.store
    search = search or (lambda spl, run_id: splunk.search(config, spl, run_id=run_id, count=SEARCH_ROWS + 1))
    app = FastAPI(title="RomHack workshop", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def same_origin(request: Request, call_next):
        # No login on localhost, so refuse state changes started by other websites.
        origin = request.headers.get("origin")
        if request.method == "POST" and origin and origin.split("://", 1)[-1] != request.headers.get("host"):
            return JSONResponse({"detail": "Cross-site request refused"}, status_code=403)
        return await call_next(request)

    @app.exception_handler(RequestValidationError)
    async def validation(_, exc):
        # n8n shows only the messages, so name the field in each one.
        problems = ["{}: {}".format(".".join(str(part) for part in error["loc"] if part != "body") or "body", error["msg"].lower()) for error in exc.errors()]
        return JSONResponse({"detail": "; ".join(problems)}, status_code=422)

    @app.exception_handler(InvalidRequest)
    async def invalid(_, exc):
        return JSONResponse({"detail": str(exc)}, status_code=422)

    @app.exception_handler(NotFound)
    async def not_found(_, exc):
        return JSONResponse({"detail": str(exc)}, status_code=404)

    @app.exception_handler(Rejected)
    async def rejected(_, exc):
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    # --- portal --------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    def portal():
        return portal_page.render(config)

    @app.get("/api/state")
    def state():
        current = workshop.state()
        operations = sorted(current["pending"] + current["history"], key=lambda op: op.get("completed_at") or op.get("created_at") or 0, reverse=True)[:10]
        for op in operations:
            if op.get("ttl_seconds"):
                op["expires_at"] = (store.get("expiry#" + op["id"]) or {}).get("expires_at")
        return JSONResponse({
            "phase": current["phase"], "run_id": current["run_id"], "running": current["running"], "phases": PHASES,
            "links": {"n8n": config["n8n_public_url"], "splunk": config["splunk_public_url"], "website": config["target_public_url"]},
            "production": production.status(workshop), "checklist": progress.checklist(store),
            "completed": list(progress.get(store).get("done", {})),
            "alerts": [{**alert["payload"], "status": alert["status"], "attempts": alert["attempts"], "last_error": alert.get("last_error", ""),
                        "evidence_status": alert.get("evidence_status", ""), "created_at": alert["created_at"]} for alert in reversed(workshop.alerts())],
            "operations": operations, "approvals": workshop.approvals(),
        }, headers={"Cache-Control": "no-store"})

    @app.post("/api/start")
    def start(body: Phase):
        return workshop.start(body.phase)

    @app.post("/api/replay")
    def replay():
        return workshop.start()

    @app.post("/api/stop")
    def stop():
        return workshop.stop()

    @app.get("/workflows/{phase}.json")
    def workflow(phase: str):
        if phase not in PHASES:
            raise HTTPException(404)
        path = Path(config["workflows_dir"]) / f"{phase}.json"
        if not path.is_file():
            raise HTTPException(404, "Workflow file missing")
        return FileResponse(path, filename=f"romhack-{phase}.json", media_type="application/json")

    @app.get("/favicon.ico")
    def favicon():
        return FileResponse(str(ASSETS.joinpath("goku.png")), media_type="image/png")

    @app.get("/assets/{name}")
    def asset(name: str):
        if "/" in name or not ASSETS.joinpath(name).is_file():
            raise HTTPException(404)
        return FileResponse(str(ASSETS.joinpath(name)), headers={"Cache-Control": "max-age=3600"})

    # --- API used by the workflow -------------------------------------
    @app.post("/api/alerts", status_code=202)
    def receive_alert(body: dict):
        return workshop.alert(body)

    @app.post("/api/remediations", status_code=202)
    def remediation(body: Action):
        return workshop.action(body.model_dump())

    @app.get("/api/operations/{operation_id}")
    def operation(operation_id: str):
        value = workshop.operation(operation_id)
        if not value:
            raise HTTPException(404, "Operation not found")
        return value

    @app.post("/api/audit", status_code=202)
    def audit(body: Audit):
        if len(str(body.decision)) > 100:
            raise InvalidRequest("Audit decision exceeds the workshop limit")
        return workshop.audit(body.model_dump())

    @app.get("/api/intelligence/{kind}")
    def intel(kind: str, ip: str):
        if kind not in ("reputation", "context"):
            raise HTTPException(404, "Unknown intelligence service")
        from ipaddress import IPv4Address
        try:
            address = str(IPv4Address(ip))
        except ValueError as exc:
            raise HTTPException(422, "Expected IPv4 address") from exc
        try:
            return lookup(address, kind)
        except RuntimeError as exc:
            raise HTTPException(503, str(exc)) from exc

    @app.post("/api/search")
    def run_search(body: Search):
        workshop.ready(body.run_id)
        try:
            rows, truncated = fit(search(body.search, body.run_id))
        except splunk.QueryError as exc:
            raise HTTPException(400, str(exc)) from exc
        except (RuntimeError, ValueError, httpx.HTTPError) as exc:
            raise HTTPException(502, f"Splunk search failed: {exc}") from exc
        result = {"results": rows, "truncated": truncated}
        if truncated:
            result["note"] = f"Only the first {len(rows)} rows are shown. Narrow the search or summarize with | stats."
        return result

    @app.post("/api/approvals", status_code=201)
    def register_approval(body: Approval):
        return workshop.register_approval(body.url, body.run_id, body.src_ip)

    @app.get("/api/approvals/{approval_id}")
    def approval(approval_id: str):
        return workshop.approval(approval_id)

    @app.post("/api/approvals/{approval_id}/validate")
    def validate_approval(approval_id: str):
        return workshop.decide_approval(approval_id, approved=True)

    @app.post("/api/approvals/{approval_id}/deny")
    def deny_approval(approval_id: str):
        return workshop.decide_approval(approval_id, approved=False)

    return app
