from __future__ import annotations

from contextlib import asynccontextmanager
from io import BytesIO
import os
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import ledger
from .evidence import create_evidence_bundle, load_evidence_bundle
from .auth import (
    ROLE_LABELS, activate_enrollment, authenticate, change_password, create_account,
    current_user, require_user, set_account_status,
)
from .reporting import build_forensic_report
from .service import create_package, decrypt_and_fingerprint, investigate, verify_event
from .store import (
    DATA, EVIDENCE, OUTPUTS, TRUST_ANCHOR_FILE, all_people, list_outputs, list_packages, new_id, now_iso,
    provision, public_key_fingerprint, read_json, recipient_paths, recipient_registry,
)


ROOT = Path(__file__).resolve().parent.parent


@asynccontextmanager
async def lifespan(_: FastAPI):
    provision()
    yield


app = FastAPI(title="Project Aegis", version="0.1.0", lifespan=lifespan)
DATA.mkdir(parents=True, exist_ok=True)
secret_path = DATA / "session-secret"
if not secret_path.exists():
    secret_path.write_text(os.urandom(32).hex(), "utf-8")
app.add_middleware(
    SessionMiddleware,
    secret_key=secret_path.read_text("utf-8").strip(),
    session_cookie="aegis_session",
    same_site="strict",
    https_only=False,
    max_age=60 * 60 * 4,
)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
templates = Jinja2Templates(directory=ROOT / "templates")


def context(request: Request, **extra):
    people = all_people()
    packages = list_packages()
    outputs = list_outputs()
    ledger_status = ledger.verify_chain()
    chain = ledger.primary_chain()
    active_recipients = sum(
        1 for person in people.values()
        if person.get("role") == "recipient" and person.get("active")
    )
    decryption_events = [
        block for block in chain
        if block.get("event", {}).get("schema") == "aegis.decryption.v1"
    ]
    return {
        "request": request,
        "user": current_user(request),
        "role_labels": ROLE_LABELS,
        "recipients": recipient_registry(),
        "people": people,
        "packages": packages,
        "outputs": outputs,
        "ledger_status": ledger_status,
        "readiness": {
            "active_recipients": active_recipients,
            "encrypted_packages": len(packages),
            "decryption_events": len(decryption_events),
            "ledger_height": ledger_status["height"],
            "validators_ready": ledger_status["valid"] and len(ledger_status["node_heads"]) == 4,
            "latest_event_id": decryption_events[-1]["event"]["event_id"] if decryption_events else None,
        },
        **extra,
    }


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    if exc.status_code == 401:
        return RedirectResponse("/login", status_code=303)
    if exc.status_code == 428:
        return RedirectResponse("/account/password", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="error.html",
        context=context(request, status_code=exc.status_code, error=exc.detail),
        status_code=exc.status_code,
    )


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context=context(request))


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if current_user(request):
        return RedirectResponse("/workspace", status_code=303)
    return templates.TemplateResponse(request=request, name="login.html", context=context(request))


@app.post("/login", response_class=HTMLResponse)
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    user = authenticate(username, password)
    if not user:
        return templates.TemplateResponse(
            request=request, name="login.html",
            context=context(request, error="The username or passphrase is incorrect."),
            status_code=401,
        )
    request.session.clear()
    request.session["user"] = user
    return RedirectResponse("/account/password" if user.get("must_change_password") else "/workspace", status_code=303)


@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("aegis_session")
    return response


@app.get("/workspace", response_class=HTMLResponse)
async def workspace(request: Request):
    require_user(request)
    return templates.TemplateResponse(request=request, name="workspace.html", context=context(request))


@app.get("/account/password", response_class=HTMLResponse)
async def password_page(request: Request):
    require_user(request, allow_password_change=True)
    return templates.TemplateResponse(request=request, name="password.html", context=context(request))


@app.post("/account/password", response_class=HTMLResponse)
async def password_update(request: Request, current_password: str = Form(...), new_password: str = Form(...), confirm_password: str = Form(...)):
    user = require_user(request, allow_password_change=True)
    if new_password != confirm_password:
        return templates.TemplateResponse(request=request, name="password.html", context=context(request, error="New passphrases do not match."), status_code=400)
    try:
        updated = change_password(user["username"], current_password, new_password)
        request.session["user"] = updated
        return RedirectResponse("/workspace?credential=updated", status_code=303)
    except Exception as exc:
        return templates.TemplateResponse(request=request, name="password.html", context=context(request, error=str(exc)), status_code=400)


@app.post("/admin/trusted-people", response_class=HTMLResponse)
async def add_trusted_person(
    request: Request,
    full_name: str = Form(...),
    username: str = Form(...),
    department: str = Form(...),
    role: str = Form(...),
    temporary_password: str = Form(...),
):
    actor = require_user(request, {"administrator"})
    try:
        account = create_account(full_name, username, department, role, temporary_password, actor["username"])
        event = {
            "schema": "aegis.identity.v1",
            "event_id": new_id("evt"),
            "identity_id": account["username"],
            "identity_name": account["name"],
            "department": account["department"],
            "role": account["role"],
            "created_by": actor["username"],
            "created_at": account["created_at"],
        }
        if role == "recipient":
            paths = recipient_paths(account["username"])
            event["kem_algorithm"] = "ML-KEM-768 (FIPS 203)"
            event["kem_key_id"] = public_key_fingerprint(paths["kem_public"])
            event["kem_public_key_pem"] = paths["kem_public"].read_text("utf-8")
            event["signature_algorithm"] = "ML-DSA-65 (FIPS 204)"
            event["signing_key_id"] = public_key_fingerprint(paths["sign_public"])
            event["signing_public_key_pem"] = paths["sign_public"].read_text("utf-8")
        block = ledger.append_event(event)
        activate_enrollment(account["username"])
        message = f"{account['name']} is trusted. Enrollment was committed at ledger block #{block['height']}."
        return templates.TemplateResponse(request=request, name="workspace.html", context=context(request, success=message))
    except Exception as exc:
        return templates.TemplateResponse(request=request, name="workspace.html", context=context(request, error=str(exc)), status_code=400)


@app.post("/admin/trusted-people/{username}/status", response_class=HTMLResponse)
async def update_trusted_person_status(request: Request, username: str, active: str = Form(...)):
    actor = require_user(request, {"administrator"})
    try:
        enabled = active == "true"
        people = all_people()
        target = people.get(username)
        if not target:
            raise ValueError("Trusted identity does not exist")
        if target.get("role") == "administrator":
            raise ValueError("The bootstrap administrator cannot be suspended")
        event = {
            "schema": "aegis.identity.status.v1",
            "event_id": new_id("evt"),
            "identity_id": username,
            "identity_name": target["name"],
            "status": "active" if enabled else "suspended",
            "changed_by": actor["username"],
            "changed_at": now_iso(),
        }
        block = ledger.append_event(event)
        account = set_account_status(username, enabled, actor["username"])
        return templates.TemplateResponse(request=request, name="workspace.html", context=context(request, success=f"{account['name']} is now {event['status']}. Change committed at block #{block['height']}."))
    except Exception as exc:
        return templates.TemplateResponse(request=request, name="workspace.html", context=context(request, error=str(exc)), status_code=400)


@app.post("/distribute", response_class=HTMLResponse)
async def distribute(request: Request, document: UploadFile = File(...), recipients: list[str] = Form(...)):
    require_user(request, {"administrator"})
    try:
        content = await document.read()
        if len(content) > 25 * 1024 * 1024:
            raise ValueError("MVP file limit is 25 MB")
        package = create_package(document.filename or "document.pdf", content, recipients)
        return templates.TemplateResponse(request=request, name="workspace.html", context=context(request, success=f"Encrypted package {package['package_id']} created for {len(recipients)} recipients."))
    except Exception as exc:
        return templates.TemplateResponse(request=request, name="workspace.html", context=context(request, error=str(exc)), status_code=400)


@app.post("/decrypt", response_class=HTMLResponse)
async def decrypt(request: Request, package_id: str = Form(...), password: str = Form(...)):
    user = require_user(request, {"recipient"})
    try:
        result = decrypt_and_fingerprint(package_id, user["username"], password)
        return templates.TemplateResponse(request=request, name="result.html", context=context(request, result=result))
    except Exception as exc:
        return templates.TemplateResponse(request=request, name="workspace.html", context=context(request, error=str(exc)), status_code=400)


@app.get("/download/{output_id}")
async def download(request: Request, output_id: str):
    user = require_user(request)
    metadata = read_json(OUTPUTS / f"{output_id}.json")
    if not metadata:
        raise HTTPException(404, "Output not found")
    if user["role"] == "recipient" and metadata.get("recipient_id") != user["username"]:
        raise HTTPException(403, "This forensic copy belongs to another recipient session")
    path = Path(metadata["path"])
    if not path.exists() or path.parent.resolve() != OUTPUTS.resolve():
        raise HTTPException(404, "Output file not found")
    return FileResponse(path, media_type="application/pdf", filename=metadata["filename"])


@app.get("/sample")
async def sample(request: Request):
    require_user(request, {"administrator"})
    return FileResponse(DATA / "sample-confidential.pdf", media_type="application/pdf", filename="sample-confidential.pdf")


@app.post("/investigate", response_class=HTMLResponse)
async def investigate_upload(request: Request, leaked_document: UploadFile = File(...)):
    require_user(request, {"investigator", "administrator"})
    try:
        content = await leaked_document.read()
        result = investigate(content)
        if result.get("status") == "verified":
            request.session["last_verified_event"] = result["block"]["event"]["event_id"]
            if result["evidence"].get("identity_binding_temporal_valid"):
                bundle = create_evidence_bundle(result, leaked_document.filename)
                result["bundle_id"] = bundle["bundle_id"]
        return templates.TemplateResponse(request=request, name="investigate.html", context=context(request, result=result, filename=leaked_document.filename))
    except Exception as exc:
        return templates.TemplateResponse(request=request, name="workspace.html", context=context(request, error=str(exc)), status_code=400)


@app.get("/ledger", response_class=HTMLResponse)
async def ledger_view(request: Request, identity: str = "", event_type: str = "", document_id: str = "", date: str = "", block: str = ""):
    require_user(request, {"investigator", "administrator"})
    complete_chain = list(reversed(ledger.primary_chain()))
    filtered_chain = complete_chain
    identity_query = identity.strip().lower()
    document_query = document_id.strip().lower()
    block_query = block.strip().lstrip("#")
    if identity_query:
        filtered_chain = [item for item in filtered_chain if identity_query in " ".join([
            str(item.get("event", {}).get("recipient_id", "")), str(item.get("event", {}).get("recipient_name", "")),
            str(item.get("event", {}).get("identity_id", "")), str(item.get("event", {}).get("identity_name", "")),
        ]).lower()]
    if event_type:
        filtered_chain = [item for item in filtered_chain if item.get("event", {}).get("schema") == event_type]
    if document_query:
        filtered_chain = [item for item in filtered_chain if document_query in str(item.get("event", {}).get("document_id", "")).lower()]
    if date:
        filtered_chain = [item for item in filtered_chain if str(item.get("timestamp", "")).startswith(date)]
    if block_query:
        filtered_chain = [item for item in filtered_chain if str(item.get("height")) == block_query or str(item.get("block_hash", "")).lower().startswith(block_query.lower())]
    filters = {"identity": identity, "event_type": event_type, "document_id": document_id, "date": date, "block": block}
    return templates.TemplateResponse(request=request, name="ledger.html", context=context(request, chain=filtered_chain, total_blocks=len(complete_chain), filters=filters))


@app.get("/evidence/report/{event_id}")
async def evidence_report(request: Request, event_id: str):
    require_user(request, {"investigator", "administrator"})
    block = ledger.find_by_event(event_id)
    if not block or block.get("event", {}).get("schema") != "aegis.decryption.v1":
        raise HTTPException(404, "Decryption evidence event not found")
    report = build_forensic_report(block, verify_event(block))
    filename = f"aegis-evidence-{event_id}.pdf"
    return StreamingResponse(BytesIO(report), media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.get("/evidence/bundle/{bundle_id}")
async def evidence_bundle(request: Request, bundle_id: str):
    require_user(request, {"investigator", "administrator"})
    if not load_evidence_bundle(bundle_id):
        raise HTTPException(404, "Portable evidence bundle not found")
    return FileResponse(EVIDENCE / f"{bundle_id}.json", media_type="application/json", filename=f"aegis-{bundle_id}.json")


@app.get("/evidence/trust-anchor")
async def evidence_trust_anchor(request: Request):
    require_user(request, {"investigator", "administrator"})
    return FileResponse(TRUST_ANCHOR_FILE, media_type="application/json", filename="aegis-offline-trust-anchor.json")


@app.get("/api/health")
async def health():
    return {"status": "ok", "offline": True, "ledger": ledger.verify_chain()}
