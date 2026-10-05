"""refagent: title availability, from the rights table and one tool (SPEC/01 §6, ruling SCOPE).

Sonnet 4.6 through the pinned inference profile, one tool, no knowledge base,
no HITL branch and no memory: cuts 1, 3 and 4 are taken at M01 open
(`milestones/M01/feasibility.md` §2.6). What is left is the claim's own
half: refagent answers an ordinary golden, and the answer carries a
`table_row` and a `clause_id` that exist (F1.4).

Two things this file is careful about.

**The rights table is the truth** (SPEC/00 §9). `check_availability`
returns one row and the clauses it can be read under. It does not decide
whether we may publish; the model does, from the row. A tool that returned
the verdict would make F1.4 a test of the tool.

**Where the row is read from.** The deployed runtime reads the DynamoDB
table `GovernedAgent` creates. A run in the CI runner — which is what M01
PR 2 measures, because the agent stack is deployed from `main` after PR 2
merges — reads `data/rights_table.json`, the file the table is loaded
from. Every observation records which, in `source`, so the envelope says
what it read.

This module judges nothing and writes no envelope (P5).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

BUNDLE = Path(__file__).parent
ROOT = BUNDLE.parents[1]
PROMPT = (BUNDLE / "prompt.txt").read_text(encoding="utf-8")
CONTRACT = json.loads((BUNDLE / "tools" / "check_availability.json").read_text(encoding="utf-8"))
MANIFEST_PATH = BUNDLE / "manifest.yaml"

INFERENCE_CONFIG = {"temperature": 0, "maxTokens": 1024}
MAX_TOOL_CALLS = 2  # one call, and one more if the model corrects its arguments

# Which clauses a row can be read under, by what the row says. The tool hands
# the candidates over; the question decides which one, and that is the
# model's to say (Tool Owner, the contract's `clause_candidates`).
ALWAYS = ["ML-2.1", "ML-2.3"]
BY_FIELD = {
    "window": ["ML-3.1"],
    "holdback_until": ["HS-2", "HS-4"],
    "clearance_expiry": ["MC-3", "MC-4"],
    "embargo_lift_local": ["EM-1", "EM-2"],
    "non_exclusive": ["ML-5.2"],
}


def rights_rows(table_name: str | None, client: Any | None = None) -> tuple[list[dict[str, Any]], str]:
    """Every row, and where it was read. DynamoDB when there is a table, else the file."""
    if table_name and client is not None:
        rows = []
        pages = client.get_paginator("scan").paginate(TableName=table_name)
        for page in pages:
            rows += [{k: _plain(v) for k, v in item.items()} for item in page["Items"]]
        return rows, "dynamodb"
    return json.loads((ROOT / "data" / "rights_table.json").read_text(encoding="utf-8")), "data/rights_table.json"


def _plain(value: dict[str, Any]) -> Any:
    """One DynamoDB attribute, as the JSON file holds it."""
    if "S" in value:
        return value["S"]
    if "BOOL" in value:
        return value["BOOL"]
    if "NULL" in value:
        return None
    raise ValueError(f"unexpected attribute {value!r}")


def check_availability(arguments: dict[str, Any], rows: list[dict[str, Any]], source: str) -> dict[str, Any]:
    """The tool. One row, and the clauses it can be read under. It decides nothing."""
    _refuse_unless_valid(arguments, CONTRACT["input"], "arguments")
    match = [
        row for row in rows
        if row["title_id"] == arguments["title_id"]
        and row["territory"] == arguments["territory"]
        and row["platform"] == arguments["platform"]
    ]  # fmt: skip
    if len(match) > 1:
        # The tool returns "the governing row". Two rows on one key means the
        # table does not say which governs, and choosing quietly would make
        # that the tool's decision. Nothing holds the key unique today.
        raise ValueError(
            f"check_availability: {len(match)} rows for "
            f"{arguments['title_id']}/{arguments['territory']}/{arguments['platform']}: "
            + ", ".join(row["table_row"] for row in match)
        )
    if not match:
        # No row is an answer: a grant that is not scheduled does not exist.
        result = {"found": False, "row": None, "clause_candidates": ["ML-2.1"], "source": source}
    else:
        row = match[0]
        candidates = list(ALWAYS) + BY_FIELD["window"]
        for field in ("holdback_until", "clearance_expiry", "embargo_lift_local"):
            if row.get(field):
                candidates += BY_FIELD[field]
        if not row["exclusive"]:
            candidates += BY_FIELD["non_exclusive"]
        result = {"found": True, "row": row, "clause_candidates": candidates, "source": source}
    _refuse_unless_valid(result, CONTRACT["output"], "result")
    return result


def _refuse_unless_valid(value: Any, schema: dict[str, Any], what: str) -> None:
    """Strict, both ways (Tool Owner). A tool that accepts what its schema forbids has no schema."""
    from jsonschema import Draft202012Validator

    errors = sorted(Draft202012Validator(schema).iter_errors(value), key=str)
    if errors:
        raise ValueError(f"check_availability {what}: " + "; ".join(e.message for e in errors))


def tool_config() -> dict[str, Any]:
    return {"tools": [{"toolSpec": {
        "name": CONTRACT["name"],
        "description": CONTRACT["description"],
        "inputSchema": {"json": CONTRACT["input"]},
    }}]}  # fmt: skip


def parse_json(text: str) -> dict[str, Any] | None:
    """The outermost JSON object in the reply, or None. No repair (as the control does it)."""
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        parsed = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def guardrail_config(guardrail: dict[str, str] | None) -> dict[str, Any]:
    """converse's guardrailConfig for the manifest's pin, or nothing when there is none (M03 PR 2)."""
    if not guardrail:
        return {}
    return {"guardrailConfig": {"guardrailIdentifier": guardrail["id"], "guardrailVersion": guardrail["version"],
                                "trace": "enabled"}}  # fmt: skip


def question_content(question: str, guardrail: dict[str, str] | None) -> list[dict[str, Any]]:
    """The user's turn. Under a guardrail, the question is the only input it assesses (guardContent).

    The system prompt and the tool's results (the rights table's rows) are
    not the user's words; the probe of the deployed guardrail assessed the
    question alone, and the run assesses what the probe did. The model
    reads guardContent as it reads text. The answer is assessed whole.
    """
    return [{"guardContent": {"text": {"text": question}}}] if guardrail else [{"text": question}]


def intervening_topics(trace: dict[str, Any]) -> list[str]:
    """Every denied topic the guardrail's trace says it blocked on, input and output (rule-owner F3; commit 13)."""
    found: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for topic in node.get("topicPolicy", {}).get("topics", []):
                if topic.get("action") == "BLOCKED":
                    found.add(topic["name"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(trace.get("guardrail", {}))
    return sorted(found)


def answer(client: Any, question: str, model_id: str, rows: list[dict[str, Any]], source: str,
           guardrail: dict[str, str] | None = None) -> dict[str, Any]:  # fmt: skip
    """Converse, with the tool, until the model answers. Returns the raw observation; judges nothing.

    `guardrail` is the manifest's pin, `{"id", "version"}`, or None: the
    runner passes it from the manifest, the runtime from the environment
    GovernedAgent sets from the same manifest.
    """
    started = time.perf_counter()
    messages: list[dict[str, Any]] = [{"role": "user", "content": question_content(question, guardrail)}]
    topics: set[str] = set()
    usage = {"inputTokens": 0, "outputTokens": 0, "totalTokens": 0}
    calls: list[dict[str, Any]] = []
    stop_reason = ""

    failed = None
    for _ in range(MAX_TOOL_CALLS + 1):
        try:
            response = client.converse(
                modelId=model_id,
                system=[{"text": PROMPT}],
                messages=messages,
                inferenceConfig=INFERENCE_CONFIG,
                toolConfig=tool_config(),
                **guardrail_config(guardrail),
            )
        except (BotoCoreError, ClientError) as exc:
            # A golden that spends and then fails has still spent. Raising here
            # would throw away the usage of the calls before it, and the cap
            # exists for exactly that run (Threshold Owner, M01 PR 2).
            failed = f"{type(exc).__name__}: {exc}"
            break
        for field in usage:
            usage[field] += response["usage"].get(field, 0)
        stop_reason = response["stopReason"]
        topics.update(intervening_topics(response.get("trace", {})))
        reply = response["output"]["message"]
        messages.append(reply)
        uses = [block["toolUse"] for block in reply["content"] if "toolUse" in block]
        if not uses:
            break
        results = []
        for use in uses:
            try:
                result: Any = check_availability(use["input"], rows, source)
                status = "success"
            except ValueError as exc:  # the model's arguments, or our own result: it is told either way
                result, status = {"error": str(exc)}, "error"
            calls.append({"name": use["name"], "input": use["input"], "status": status, "output": result})
            results.append({"toolResult": {"toolUseId": use["toolUseId"],
                                           "content": [{"json": result}], "status": status}})  # fmt: skip
        messages.append({"role": "user", "content": results})

    text = "".join(block.get("text", "") for block in messages[-1]["content"] if isinstance(block, dict))
    observation = {"error": failed} if failed else {}
    return {
        **observation,
        "text": text,
        "parsed": parse_json(text),
        "stop_reason": stop_reason,
        "guardrail_topics": sorted(topics),
        "usage": usage,
        "latency_ms": round((time.perf_counter() - started) * 1000),
        "tool_calls": calls,
        "source": source,
    }
