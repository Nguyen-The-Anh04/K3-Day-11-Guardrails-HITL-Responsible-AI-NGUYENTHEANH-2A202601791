"""
Assignment 11 — Defense-in-depth pipeline assembly (TODO).

Wire rate limiter + lab guardrails + judge + audit + monitoring.
You may use Google ADK plugins, LangGraph, NeMo, or pure Python.
"""
from __future__ import annotations

import os
import json
from pathlib import Path
from urllib.parse import urlparse

from assignment.rate_limiter import RateLimitPlugin
from assignment.audit_log import AuditLogPlugin
from assignment.monitoring import MonitoringAlert
from guardrails.input_guardrails import InputGuardrailPlugin
from guardrails.output_guardrails import OutputGuardrailPlugin
from agents.security_boundary import contains_secret, normalize_for_security


# Approved VinBank HTTPS endpoints
ALLOWED_EGRESS_HOSTS = {
    "api.vinbank.example",
    "cases.vinbank.example",
}


def is_egress_allowed(destination: str, payload: str) -> bool:
    """TODO 8A: Enforce a destination allowlist before any data leaves the agent.

    Return ``True`` only for an approved VinBank HTTPS endpoint and ordinary
    banking payload. Return ``False`` for unknown domains and payloads that
    contain a password, API key, database host, phone number or email address.
    Do not let the LLM's prose decide this policy.
    """
    # 1. Parse destination
    parsed = urlparse(destination)

    # Must be HTTPS
    if parsed.scheme != "https":
        return False

    # Must be in allowlist
    hostname = parsed.hostname or ""
    if hostname not in ALLOWED_EGRESS_HOSTS:
        return False

    # 2. Check payload for secrets/PII
    normalized_payload = normalize_for_security(payload)
    if contains_secret(normalized_payload):
        return False

    # Check for phone/email in payload
    import re
    if re.search(r"0\d{9,10}", payload):  # VN phone
        return False
    if re.search(r"[\w.-]+@[\w.-]+\.[a-zA-Z]{2,}", payload):  # email
        return False

    return True


def build_production_plugins(
    *,
    max_requests: int = 10,
    window_seconds: int = 60,
    use_llm_judge: bool = True,
) -> list:
    """
    TODO 8: Return an ordered list of plugins / layers:

    1. RateLimitPlugin
    2. InputGuardrailPlugin  (from guardrails.input_guardrails)
    3. OutputGuardrailPlugin / LlmJudge  (from guardrails.output_guardrails)
    4. (optional) NeMo wrapper

    Audit/monitoring can be plugins or side observers — document your choice.
    The action gateway calls ``is_egress_allowed`` separately before any sink.
    """
    plugins = [
        RateLimitPlugin(max_requests=max_requests, window_seconds=window_seconds),
        InputGuardrailPlugin(),
        OutputGuardrailPlugin(use_llm_judge=use_llm_judge),
    ]
    return plugins


def build_observability():
    """TODO: return (AuditLogPlugin(), MonitoringAlert())."""
    return AuditLogPlugin(), MonitoringAlert()


async def run_assignment_suite(pipeline, student_id: str) -> dict:
    """
    TODO: Run Tests 1–4 from assignment11.md and
    return a dict matching schemas/results.schema.json.

    Write:
      outputs/results.json
      outputs/audit_log.json
      outputs/metrics.json
    """
    from testing.testing import SecurityTestPipeline
    from agents.agent import create_unsafe_agent, create_protected_agent

    # Build protected agent with plugins
    plugins = pipeline.get("plugins", [])
    protected_agent, protected_runner = create_protected_agent(plugins=plugins)

    # Run security tests
    test_pipeline = SecurityTestPipeline(protected_agent, protected_runner)
    results = await test_pipeline.run_all()

    # Calculate metrics
    metrics = test_pipeline.calculate_metrics(results)

    # Build output
    output = {
        "student_id": student_id,
        "timestamp": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat(),
        "tests": {
            "total": metrics["total"],
            "blocked": metrics["blocked"],
            "leaked": metrics["leaked"],
            "block_rate": metrics["block_rate"],
            "leak_rate": metrics["leak_rate"],
        },
        "results": [
            {
                "id": r.attack_id,
                "category": r.category,
                "blocked": r.blocked,
                "leaked_secrets": r.leaked_secrets,
            }
            for r in results
        ],
    }

    # Write outputs
    out_dir = Path(__file__).resolve().parents[1] / "outputs"
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "results.json").write_text(
        json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # Audit log
    audit = pipeline.get("audit")
    if audit:
        audit.export_json(str(out_dir / "audit_log.json"))

    # Metrics
    monitor = pipeline.get("monitoring")
    if monitor:
        monitor.export_json(str(out_dir / "metrics.json"))

    return output
