"""ai-guardrail-create-active-delete-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ai-guardrail-create-active-delete-lifecycle"
GROUP = "lifecycle"
SERVICES = ["qconnect"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAIGuardrail reaches ACTIVE and DeleteAIGuardrail makes GetAIGuardrail 404."""
    qc = ctx.client("qconnect")
    assistant_id = _create_active_assistant(ctx, qc)

    name = ctx.unique_name("sim2real-qc-guard-")
    created_guardrail = qc.create_ai_guardrail(
        assistantId=assistant_id,
        name=name,
        blockedInputMessaging="I can't help with that request.",
        blockedOutputsMessaging="I can't provide that response.",
        visibilityStatus="SAVED",
    )["aiGuardrail"]
    guardrail_id = created_guardrail["aiGuardrailId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: qc.delete_ai_guardrail(assistantId=assistant_id, aiGuardrailId=guardrail_id)
        )
    )

    status = created_guardrail.get("status")
    if status != "ACTIVE":
        updated_guardrail = _poll_until(
            lambda: qc.get_ai_guardrail(assistantId=assistant_id, aiGuardrailId=guardrail_id)["aiGuardrail"],
            lambda g: g["status"] in ("ACTIVE", "CREATE_FAILED"),
            timeout_s=220.0,
            interval_s=8.0,
        )
        status = updated_guardrail["status"]
    assert status == "ACTIVE", f"guardrail did not reach ACTIVE, got {status}"

    qc.delete_ai_guardrail(assistantId=assistant_id, aiGuardrailId=guardrail_id)

    def _get_code():
        try:
            qc.get_ai_guardrail(assistantId=assistant_id, aiGuardrailId=guardrail_id)
            return None
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")

    code = _poll_until(_get_code, lambda c: c is not None, timeout_s=60.0)
    assert code == ("ResourceNotFoundException", "AI Guardrail does not exist."), f"expected ResourceNotFoundException, got {code}"


def _create_active_assistant(ctx, qc) -> str:
    name = ctx.unique_name("sim2real-qc-asst-")
    assistant_id = qc.create_assistant(name=name, type="AGENT")["assistant"]["assistantId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: qc.delete_assistant(assistantId=assistant_id)))
    status = _poll_until(
        lambda: qc.get_assistant(assistantId=assistant_id)["assistant"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert status == "ACTIVE", f"prerequisite assistant did not reach ACTIVE, got {status}"
    return assistant_id


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
