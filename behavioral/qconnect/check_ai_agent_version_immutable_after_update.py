"""ai-agent-version-immutable-after-update."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ai-agent-version-immutable-after-update"
GROUP = "versioning"
SERVICES = ["qconnect"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAIAgent mutates only $LATEST; a previously published numbered version stays frozen."""
    qc = ctx.client("qconnect")
    assistant_id = _create_active_assistant(ctx, qc)

    name = ctx.unique_name("sim2real-qc-agent-")
    agent_id = qc.create_ai_agent(
        assistantId=assistant_id,
        name=name,
        type="MANUAL_SEARCH",
        configuration={"manualSearchAIAgentConfiguration": {}},
        visibilityStatus="SAVED",
        description="original-description",
        tags={"sim2real": "true"},
    )["aiAgent"]["aiAgentId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: qc.delete_ai_agent(assistantId=assistant_id, aiAgentId=agent_id))
    )
    _poll_until(
        lambda: _get_agent_or_none(qc, assistant_id, agent_id),
        lambda a: a is not None,
        timeout_s=120.0,
        interval_s=5.0,
    )
    qc.update_ai_agent(assistantId=assistant_id, aiAgentId=agent_id, visibilityStatus="PUBLISHED")
    _poll_until(
        lambda: qc.get_ai_agent(assistantId=assistant_id, aiAgentId=agent_id)["aiAgent"]["visibilityStatus"],
        lambda s: s == "PUBLISHED",
        timeout_s=30.0,
    )

    version = _poll_until(
        lambda: _try_create_version(qc, assistant_id, agent_id),
        lambda v: v is not None,
        timeout_s=30.0,
    )["versionNumber"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: qc.delete_ai_agent_version(assistantId=assistant_id, aiAgentId=agent_id, versionNumber=version)
        )
    )

    qc.update_ai_agent(
        assistantId=assistant_id,
        aiAgentId=agent_id,
        visibilityStatus="PUBLISHED",
        description="updated-description",
    )

    latest = qc.get_ai_agent(assistantId=assistant_id, aiAgentId=agent_id)["aiAgent"]
    assert latest["description"] == "updated-description", (
        f"expected $LATEST to reflect the update, got {latest['description']!r}"
    )

    frozen = qc.get_ai_agent(assistantId=assistant_id, aiAgentId=f"{agent_id}:{version}")["aiAgent"]
    assert frozen["description"] == "original-description", "published version must not reflect later updates"


def _create_active_assistant(ctx, qc) -> str:
    name = ctx.unique_name("sim2real-qc-asst-")
    assistant_id = qc.create_assistant(name=name, type="AGENT", tags={"sim2real": "true"})["assistant"][
        "assistantId"
    ]
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


def _get_agent_or_none(qc, assistant_id, agent_id):
    try:
        return qc.get_ai_agent(assistantId=assistant_id, aiAgentId=agent_id)["aiAgent"]
    except ClientError:
        return None


def _try_create_version(qc, assistant_id, agent_id):
    try:
        return qc.create_ai_agent_version(assistantId=assistant_id, aiAgentId=agent_id)
    except ClientError:
        return None


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
