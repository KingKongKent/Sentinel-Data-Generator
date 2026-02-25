"""Azure Function App — Live Brute Force Demo API.

Receives PIN guesses from the demo web UI and logs every attempt
to the BruteForceDemo_CL table in Microsoft Sentinel via the
Azure Monitor Logs Ingestion API.
"""

from __future__ import annotations

import datetime
import json
import logging
import os

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.monitor.ingestion import LogsIngestionClient

logger = logging.getLogger(__name__)

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# ---------------------------------------------------------------------------
# Singleton clients (reused across invocations in the same host instance)
# ---------------------------------------------------------------------------
_credential: DefaultAzureCredential | None = None
_client: LogsIngestionClient | None = None


def _get_client() -> LogsIngestionClient:
    """Return a cached LogsIngestionClient instance."""
    global _credential, _client  # noqa: PLW0603
    if _client is None:
        dce_endpoint = os.environ["DCE_ENDPOINT"]
        _credential = DefaultAzureCredential()
        _client = LogsIngestionClient(
            endpoint=dce_endpoint,
            credential=_credential,
        )
        logger.info("LogsIngestionClient initialised for %s", dce_endpoint)
    return _client


# ---------------------------------------------------------------------------
# POST /api/attempt
# ---------------------------------------------------------------------------
@app.function_name("attempt")
@app.route(route="attempt", methods=["POST"])
def attempt(req: func.HttpRequest) -> func.HttpResponse:
    """Handle a brute-force PIN guess.

    Request body (JSON):
        { "nickname": "alice", "pincode": "1337" }

    Response (JSON):
        { "result": "Success" | "Failure", "nickname": "alice" }
    """
    # --- Parse request ---
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "Invalid JSON body"}),
            status_code=400,
            mimetype="application/json",
        )

    nickname = (body.get("nickname") or "").strip()
    pincode = (body.get("pincode") or "").strip()

    if not nickname or not pincode:
        return func.HttpResponse(
            json.dumps({"error": "nickname and pincode are required"}),
            status_code=400,
            mimetype="application/json",
        )

    if not pincode.isdigit() or len(pincode) != 4:
        return func.HttpResponse(
            json.dumps({"error": "pincode must be exactly 4 digits"}),
            status_code=400,
            mimetype="application/json",
        )

    # --- Evaluate attempt ---
    secret_pin = os.environ.get("SECRET_PIN", "1337")
    result = "Success" if pincode == secret_pin else "Failure"

    # --- Build log record ---
    source_ip = (
        req.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or req.headers.get("X-Real-IP", "")
        or "unknown"
    )
    user_agent = req.headers.get("User-Agent", "unknown")

    record = {
        "TimeGenerated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "Nickname": nickname[:50],  # cap length
        "Pincode": pincode,
        "AttemptResult": result,
        "SourceIP": source_ip,
        "UserAgent": user_agent[:256],  # cap length
    }

    # --- Send to Sentinel ---
    dcr_id = os.environ["DCR_IMMUTABLE_ID"]
    stream_name = os.environ.get("STREAM_NAME", "Custom-BruteForceDemo_CL")

    try:
        client = _get_client()
        client.upload(
            rule_id=dcr_id,
            stream_name=stream_name,
            logs=[record],
        )
        logger.info("Logged attempt: %s → %s", nickname, result)
    except Exception:
        logger.exception("Failed to send attempt to Sentinel")
        # Still return the result to the user — don't break the demo
        # if ingestion has a transient error.

    # --- Respond ---
    return func.HttpResponse(
        json.dumps({"result": result, "nickname": nickname}),
        status_code=200,
        mimetype="application/json",
        headers={"Access-Control-Allow-Origin": "*"},
    )


# ---------------------------------------------------------------------------
# OPTIONS /api/attempt  (CORS preflight)
# ---------------------------------------------------------------------------
@app.function_name("attempt_options")
@app.route(route="attempt", methods=["OPTIONS"])
def attempt_options(req: func.HttpRequest) -> func.HttpResponse:
    """Handle CORS preflight for the attempt endpoint."""
    return func.HttpResponse(
        status_code=204,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Max-Age": "86400",
        },
    )
