"""The simulated production website and the WAF in front of it.

Every request is logged twice, like a real deployment: the WAF records its
decision (``romhack:waf``) and, when allowed, the web server records the
request (``romhack:web``). Scenario clients identify themselves with the
``X-Romhack-Client-IP`` header; it stands in for a real source address.
"""
import hashlib
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

# Path -> (status, body, auth_outcome, application_event)
ROUTES = {
    "/": (200, "Hello RomHack!\n", "none", "public"),
    "/login": (401, {"error": "simulated failed login"}, "failure", "authentication"),
    "/session/login": (200, {"simulated": True, "authentication": "success"}, "success", "authentication"),
    "/app/home": (200, {"simulated": True, "activity": "account home"}, "none", "authenticated_use"),
    "/app/orders": (200, {"simulated": True, "activity": "view orders"}, "none", "authenticated_use"),
}
METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "PROPFIND"]
# PROPFIND matches a "known bad inputs" signature, which the WAF only counts.
SIGNATURE = "KnownBadInputs_PROPFIND_METHOD"


def create_target(workshop):
    app = FastAPI(title="RomHack production website", docs_url=None, redoc_url=None, openapi_url=None)

    @app.api_route("/{path:path}", methods=METHODS)
    async def serve(path: str, request: Request):
        path = "/" + path
        connection_ip = request.client.host if request.client else ""
        src_ip = request.headers.get("x-romhack-client-ip") or connection_ip
        run_id = request.headers.get("x-romhack-run-id", "")
        user = request.headers.get("x-romhack-user", "")[:80]
        session = request.headers.get("x-romhack-session", "")[:80]
        blocked = src_ip in workshop.state()["waf"]
        # Health probes from the workshop itself carry run_id "verification" and are not logged.
        logged = bool(run_id) and run_id != "verification"
        now = time.time()
        base = {"timestamp": now, "run_id": run_id, "src_ip": src_ip, "connection_ip": connection_ip,
                "path": path, "method": request.method, "synthetic_user": user, "synthetic_session": session}
        if logged:
            managed = request.method == "PROPFIND"
            workshop.sink([{**base, "source": "waf", "event_id": uuid.uuid4().hex, "action": "BLOCK" if blocked else "ALLOW", "uri": path,
                            "http_method": request.method, "managed_match": managed, "matched_rules": [SIGNATURE] if managed else [],
                            "terminating_rule": "workshop-blocklist" if blocked else "default-allow"}])
        if blocked:
            return PlainTextResponse("Forbidden\n", status_code=403)
        status, body, auth_outcome, application_event = ROUTES.get(path, (404, "Not found\n", "none", "public"))
        if logged:
            event_id = hashlib.sha256(f"{now}:{uuid.uuid4().hex}".encode()).hexdigest()[:32]
            workshop.sink([{**base, "source": "web", "event_id": event_id, "status": status,
                            "auth_outcome": auth_outcome, "application_event": application_event}])
        if isinstance(body, dict):
            return JSONResponse(body, status_code=status)
        return PlainTextResponse(body, status_code=status)

    return app
