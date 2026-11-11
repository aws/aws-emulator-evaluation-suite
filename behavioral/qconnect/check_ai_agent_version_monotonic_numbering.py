"""ai-agent-version-monotonic-numbering."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ai-agent-version-monotonic-numbering"
GROUP = "versioning"
SERVICES = ["qconnect"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAIAgentVersion assigns strictly increasing version numbers starting at 1."""
    qc = ctx.client("qconnect")
    assistant_id = _create_active_assistant(ctx, qc)

    name = ctx.unique_name("sim2real-qc-agent-")
    agent_id = qc.create_ai_agent(
        assistantId=assistant_id,
        name=name,
        type="MANUAL_SEARCH",
        configuration={"manualSearchAIAgentConfiguration": {}},
        visibilityStatus="SAVED",
        tags={"sim2real": CHECK},
    )["aiAgent"]["aiAgentId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: qc.delete_ai_agent(assistantId=assistant_id, aiAgentId=agent_id))
    )
    # GetAIAgent 404s on a SAVED (unpublished) agent even though CreateAIAgent, UpdateAIAgent and
    # ListAIAgents all see it immediately, so there is nothing to poll for before publishing it.
    qc.update_ai_agent(assistantId=assistant_id, aiAgentId=agent_id, visibilityStatus="PUBLISHED")
    _poll_until(
        lambda: qc.get_ai_agent(assistantId=assistant_id, aiAgentId=agent_id)["aiAgent"]["visibilityStatus"],
        lambda s: s == "PUBLISHED",
        timeout_s=30.0,
    )

    v1 = _poll_until(
        lambda: _try_create_version(qc, assistant_id, agent_id),
        lambda v: v is not None,
        timeout_s=30.0,
    )["versionNumber"]
    v2 = qc.create_ai_agent_version(assistantId=assistant_id, aiAgentId=agent_id)["versionNumber"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: qc.delete_ai_agent_version(assistantId=assistant_id, aiAgentId=agent_id, versionNumber=v2)
        )
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: qc.delete_ai_agent_version(assistantId=assistant_id, aiAgentId=agent_id, versionNumber=v1)
        )
    )

    assert v1 == 1, f"expected first version to be 1, got {v1}"
    assert v2 == 2, f"expected second version to be 2, got {v2}"

    listed = qc.list_ai_agent_versions(assistantId=assistant_id, aiAgentId=agent_id)["aiAgentVersionSummaries"]
    version_numbers = {s["versionNumber"] for s in listed}
    assert version_numbers == {1, 2}, f"expected versions {{1, 2}}, got {version_numbers}"


def _create_active_assistant(ctx, qc) -> str:
    name = ctx.unique_name("sim2real-qc-asst-")
    assistant_id = qc.create_assistant(name=name, type="AGENT", tags={"sim2real": CHECK})["assistant"]["assistantId"]
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
    if not predicate(value):
        raise TimeoutError(f"poll did not satisfy predicate within {timeout_s}s, last value={value!r}")
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
