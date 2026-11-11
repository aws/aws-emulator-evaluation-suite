"""ai-agent-visibility-status-transition."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ai-agent-visibility-status-transition"
GROUP = "state"
SERVICES = ["qconnect"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAIAgent flips visibilityStatus from SAVED to PUBLISHED and it is durably observable."""
    qc = ctx.client("qconnect")
    assistant_id = _create_active_assistant(ctx, qc)

    name = ctx.unique_name("sim2real-qc-agent-")
    created_agent = qc.create_ai_agent(
        assistantId=assistant_id,
        name=name,
        type="MANUAL_SEARCH",
        configuration={"manualSearchAIAgentConfiguration": {}},
        visibilityStatus="SAVED",
        tags=_mgmt_tags(),
    )["aiAgent"]
    agent_id = created_agent["aiAgentId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: qc.delete_ai_agent(assistantId=assistant_id, aiAgentId=agent_id))
    )
    assert created_agent["visibilityStatus"] == "SAVED", (
        f"expected newly created agent to start SAVED, got {created_agent['visibilityStatus']!r}"
    )

    last_error = {}

    def _try_update():
        try:
            return qc.update_ai_agent(assistantId=assistant_id, aiAgentId=agent_id, visibilityStatus="PUBLISHED")[
                "aiAgent"
            ]
        except ClientError as exc:
            last_error["code"] = exc.response["Error"]["Code"]
            last_error["message"] = exc.response["Error"].get("Message")
            return None

    updated = _poll_until(_try_update, lambda a: a is not None, timeout_s=220.0, interval_s=8.0)
    assert updated is not None, str(last_error)
    assert updated["visibilityStatus"] == "PUBLISHED", "expected visibilityStatus to become PUBLISHED"

    confirmed = _poll_until(
        lambda: qc.get_ai_agent(assistantId=assistant_id, aiAgentId=agent_id)["aiAgent"],
        lambda a: a["visibilityStatus"] == "PUBLISHED",
        timeout_s=30.0,
    )
    assert confirmed["visibilityStatus"] == "PUBLISHED", "GetAIAgent must durably reflect the PUBLISHED transition"


def _mgmt_tags():
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-qc"}


def _get_agent_or_none(qc, assistant_id, agent_id):
    try:
        return qc.get_ai_agent(assistantId=assistant_id, aiAgentId=agent_id)["aiAgent"]
    except ClientError:
        return None


def _create_active_assistant(ctx, qc) -> str:
    name = ctx.unique_name("sim2real-qc-asst-")
    assistant_id = qc.create_assistant(name=name, type="AGENT", tags=_mgmt_tags())["assistant"]["assistantId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: qc.delete_assistant(assistantId=assistant_id)))
    _poll_until(
        lambda: qc.get_assistant(assistantId=assistant_id)["assistant"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
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
