"""refagent inside AgentCore Runtime: the two endpoints the runtime calls.

`POST /invocations` takes `{"question": "..."}` and returns the raw
observation `agent.answer` writes — the same shape the runner writes on a
PR, so the envelope does not change when the subject moves from the runner
to the deployed runtime (ruling l). `GET /ping` is the health check.

The runtime reads the rights table from DynamoDB
(`AGENTKEEL_RIGHTS_TABLE`, set by `GovernedAgent`), through the VPC's
gateway endpoint. There is no way out of that VPC (ADR-0006), so if the
variable is not set the answer is an error that says so; it does not fall
back to the file, which is not in the image (`agent.rights_rows` would try
it, so the server does not call it without a table).

The model is `AGENTKEEL_MODEL_PROFILE`, the profile `GovernedAgent` makes
from the manifest's pin, and nothing else: with no default, a runtime
started without it answers with an error rather than call a model the pin
does not name (M04 PR 2; M04 open.md row 22, item f).

From M05 PR 2 (SPEC/05 §2, §5, seed S4's reader) a request may carry `chain`,
the agents that called before this one, in order; the chain's depth is its
length plus one. A chain deeper than `AGENTKEEL_CEILING_DEPTH` (the manifest's
`ceilings.depth`, which `GovernedAgent` sets: the image has no YAML reader) is
refused **before any model call or table read**, and the refusal is written
as an event under the agent's own prefix in the security account's audit
bucket (`AGENTKEEL_AUDIT_BUCKET`, `AGENTKEEL_AUDIT_PREFIX`), with the call's
session id so the trail's record of the call can be matched to it. A runtime
with no ceiling set refuses every call rather than hold a chain to nothing.
The chain is what the caller asserts; that a caller cannot lie about it is
Identity's, at M07 (SPEC/05 §5). That the call was refused rests on this
event and on no model call by the role (self-reported, SPEC/05 §2).

This server judges nothing and writes no envelope (P5).
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import boto3

from . import agent

PORT = 8080
REGION = os.environ.get("AWS_REGION", "us-west-2")
MODEL_ID = os.environ.get("AGENTKEEL_MODEL_PROFILE")
TABLE = os.environ.get("AGENTKEEL_RIGHTS_TABLE")
# The manifest's guardrail pin, which GovernedAgent sets from the same manifest
# (M03 PR 2), as the guardrail's ARN: converse takes an id or an ARN, and the
# agent role's invoke is conditioned on the ARN at the pinned version. Both or
# neither; the image has no YAML reader to read it itself.
GUARDRAIL = ({"id": os.environ["AGENTKEEL_GUARDRAIL_ARN"], "version": os.environ["AGENTKEEL_GUARDRAIL_VERSION"]}
             if os.environ.get("AGENTKEEL_GUARDRAIL_ARN") else None)  # fmt: skip
# The header AgentCore Runtime passes the caller's runtimeSessionId in; the trail records the same id.
SESSION_HEADER = "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id"


def chain_refusal(payload: dict[str, Any], session_id: str | None) -> dict[str, Any] | None:
    """Why this call is refused for its chain, or None. Read at call time, before anything else is called."""
    chain = payload.get("chain", [])
    if not isinstance(chain, list) or not all(isinstance(agent, str) and agent for agent in chain):
        return {"refused": "a chain is a list of the agents that called before this one, by name", "depth": None}
    depth = len(chain) + 1
    try:
        ceiling = int(os.environ["AGENTKEEL_CEILING_DEPTH"])
    except (KeyError, ValueError):
        return {"refused": f"no depth ceiling is set in the runtime (AGENTKEEL_CEILING_DEPTH): a chain at depth "
                           f"{depth} is held to nothing, so it is refused", "depth": depth, "ceiling": None}  # fmt: skip
    if depth <= ceiling:
        return None
    return {"refused": f"a call chain at depth {depth} is deeper than this agent's ceiling, depth {ceiling}",
            "depth": depth, "ceiling": ceiling, "chain": chain, "session_id": session_id}  # fmt: skip


def record_refusal(refusal: dict[str, Any], s3: Any) -> dict[str, Any]:
    """Write the refusal event under the agent's own prefix in the audit bucket; say where, or why not.

    A refusal is returned whether or not it is recorded: a failed write is reported in the answer, and the
    record's absence is what the observer reads as unrecorded."""
    bucket, prefix = os.environ.get("AGENTKEEL_AUDIT_BUCKET"), os.environ.get("AGENTKEEL_AUDIT_PREFIX")
    if not bucket or not prefix:
        return {"recorded": None, "record_error": "AGENTKEEL_AUDIT_BUCKET or AGENTKEEL_AUDIT_PREFIX is not set"}
    now = datetime.now(UTC)
    key = f"{prefix}{now:%Y%m%dT%H%M%SZ}-{refusal.get('session_id') or uuid.uuid4()}.json"
    event = {"event": "chain_refused", "at": now.isoformat(timespec="seconds"), **refusal}
    try:
        s3.put_object(Bucket=bucket, Key=key, Body=json.dumps(event).encode("utf-8"),
                      ContentType="application/json", ChecksumAlgorithm="SHA256")  # fmt: skip
    except Exception as exc:  # noqa: BLE001 - the refusal stands; the missing record is the observer's to read
        return {"recorded": None, "record_error": f"{type(exc).__name__}: {exc}"}
    return {"recorded": f"s3://{bucket}/{key}"}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self._send(200 if self.path == "/ping" else 404, {"status": "healthy" if self.path == "/ping" else "no"})

    def do_POST(self) -> None:
        if self.path != "/invocations":
            return self._send(404, {"error": "only /invocations"})
        body = self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        try:
            payload = json.loads(body or b"{}")
            question = payload["question"]
        except (ValueError, KeyError, TypeError) as exc:
            return self._send(400, {"error": f"a JSON object with a question: {exc}"})
        # Seed S4's reader (M05 PR 2): the chain first, before the model, the table or anything else.
        if refusal := chain_refusal(payload, self.headers.get(SESSION_HEADER)):
            s3 = boto3.client("s3", region_name=REGION) if os.environ.get("AGENTKEEL_AUDIT_BUCKET") else None
            return self._send(403, {**refusal, **record_refusal(refusal, s3)})
        if not MODEL_ID or not TABLE:
            missing = [name for name, value in (("AGENTKEEL_MODEL_PROFILE", MODEL_ID), ("AGENTKEEL_RIGHTS_TABLE", TABLE))
                       if not value]  # fmt: skip
            return self._send(200, {"error": f"not set in the runtime: {', '.join(missing)}"})
        try:
            rows, source = agent.rights_rows(TABLE, boto3.client("dynamodb", region_name=REGION))
            self._send(200, agent.answer(self.bedrock, question, MODEL_ID, rows, source, GUARDRAIL))
        except Exception as exc:  # noqa: BLE001 - a failed call is an observation too
            self._send(200, {"error": f"{type(exc).__name__}: {exc}"})

    @property
    def bedrock(self) -> Any:
        if not hasattr(self.server, "_bedrock"):
            self.server._bedrock = boto3.client("bedrock-runtime", region_name=REGION)
        return self.server._bedrock

    def _send(self, code: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt: str, *args: Any) -> None:
        print(fmt % args)  # to the log group, not to stderr's default format


if __name__ == "__main__":
    print(f"refagent on :{PORT}, model {MODEL_ID}, table {TABLE or '(none: the file is not in the image)'}")
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
