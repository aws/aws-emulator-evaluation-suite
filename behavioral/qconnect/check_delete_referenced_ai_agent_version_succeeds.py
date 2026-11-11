"""delete-referenced-ai-agent-version-succeeds."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-referenced-ai-agent-version-succeeds"
GROUP = "state"
SERVICES = ["qconnect"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAIAgentVersion succeeds even while the version is still bound to an assistant's AI
    Agent configuration (no referential-integrity block); the version disappears from
    ListAIAgentVersions and the assistant remains otherwise unaffected."""
    qc = ctx.client("qconnect")
    assistant_id = _create_active_assistant(ctx, qc)

    name = ctx.unique_name("sim2real-qc-agent-")
    agent_id = qc.create_ai_agent(
        assistantId=assistant_id,
        name=name,
        type="MANUAL_SEARCH",
        configuration={"manualSearchAIAgentConfiguration": {}},
        visibilityStatus="SAVED",
    )["aiAgent"]["aiAgentId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: qc.delete_ai_agent(assistantId=assistant_id, aiAgentId=agent_id))
    )
    _poll_until(
        lambda: _get_agent_or_none(qc, assistant_id, agent_id),
        lambda a: a is not None,
        timeout_s=180.0,
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

    before_delete = {
        s["versionNumber"]
        for s in qc.list_ai_agent_versions(assistantId=assistant_id, aiAgentId=agent_id)["aiAgentVersionSummaries"]
    }
    assert version in before_delete, f"expected newly created version {version} to be listed, got {before_delete}"

    qc.update_assistant_ai_agent(
        assistantId=assistant_id,
        aiAgentType="MANUAL_SEARCH",
        configuration={"aiAgentId": f"{agent_id}:{version}"},
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: qc.remove_assistant_ai_agent(assistantId=assistant_id, aiAgentType="MANUAL_SEARCH")
        )
    )

    # empirically, DeleteAIAgentVersion does not enforce referential integrity against a live
    # assistant binding -- the call succeeds immediately
    qc.delete_ai_agent_version(assistantId=assistant_id, aiAgentId=agent_id, versionNumber=version)

    remaining = {
        s["versionNumber"]
        for s in qc.list_ai_agent_versions(assistantId=assistant_id, aiAgentId=agent_id)["aiAgentVersionSummaries"]
    }
    assert version not in remaining, f"expected version {version} to be gone, found {remaining}"

    # the assistant itself remains reachable and unaffected by the dangling reference
    assistant_status = qc.get_assistant(assistantId=assistant_id)["assistant"]["status"]
    assert assistant_status == "ACTIVE", f"assistant must remain ACTIVE, got {assistant_status}"


def _create_active_assistant(ctx, qc) -> str:
    name = ctx.unique_name("sim2real-qc-asst-")
    assistant_id = qc.create_assistant(name=name, type="AGENT")["assistant"]["assistantId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: qc.delete_assistant(assistantId=assistant_id)))
    _poll_until(
        lambda: qc.get_assistant(assistantId=assistant_id)["assistant"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    return assistant_id


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


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
