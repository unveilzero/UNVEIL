# routes/unveil_security_routes.py
# Read-only status for the UNVEIL security layer, an administrator-only
# control to clear a lockdown after the cause has been investigated, and a
# control for a person to release one withheld tool result of their own.
from fastapi import APIRouter, HTTPException, Request

from core.middleware import require_admin
from src.auth_helpers import require_authenticated_request, require_user
from src.unveil_guard import get_guard
from src.unveil_guard.watch import get_watch


def setup_unveil_security_routes() -> APIRouter:
    router = APIRouter(prefix="/api/unveil/security", tags=["unveil-security"])

    @router.get("/status")
    async def status(request: Request):
        owner = require_authenticated_request(request)
        report = get_guard().status()
        # Administrators see every decision; other users only their own.
        try:
            require_admin(request)
        except HTTPException:
            report["recent"] = [row for row in report["recent"] if owner and row["owner"] == owner]
        # The wording of a withheld text and its release control go only to the person it belongs to.
        report["recent"] = [
            row if row["owner"] == owner
            else {name: value for name, value in row.items() if name not in ("excerpt", "release_id")}
            for row in report["recent"]
        ]
        report["last_block"] = next((row for row in report["recent"] if row["decision"] == "BLOCK"), None)
        get_guard().describe(report)
        watch = get_watch()
        report["watch"] = watch.status() if watch is not None else None
        return report

    @router.post("/clear-lockdown")
    async def clear_lockdown(request: Request):
        require_admin(request)
        guard = get_guard()
        previous = guard.lockdown
        guard.clear_lockdown()
        return {"cleared": previous is not None, "previous_reason": previous}

    @router.post("/release/{release_id}")
    async def release(request: Request, release_id: str):
        if not get_guard().release(release_id, require_user(request)):
            raise HTTPException(404, "There is no withheld result to release.")
        return {"released": True}

    return router
