"""create-profiling-group-idempotent-with-same-client-token."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "create-profiling-group-idempotent-with-same-client-token"
GROUP = "state"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-issuing CreateProfilingGroup with the exact same profilingGroupName,
    clientToken and parameters is idempotent: it returns the same resource rather
    than a ConflictException (unlike a repeat with a different clientToken)."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-idem-")
    token = str(uuid.uuid4())
    tags_kw = {"sim2real-check": "create-profiling-group-idempotent-with-same-client-token"}

    first = cgp.create_profiling_group(
        profilingGroupName=name,
        clientToken=token,
        computePlatform="Default",
        agentOrchestrationConfig={"profilingEnabled": True},
        tags=tags_kw,
    )["profilingGroup"]
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    second = cgp.create_profiling_group(
        profilingGroupName=name,
        clientToken=token,
        computePlatform="Default",
        agentOrchestrationConfig={"profilingEnabled": True},
        tags=tags_kw,
    )["profilingGroup"]

    assert second["arn"] == first["arn"], f"expected same arn on replay, got {first['arn']!r} then {second['arn']!r}"
    assert second["name"] == first["name"], f"expected same name on replay, got {first['name']!r} then {second['name']!r}"

    # exactly one profiling group exists under this name
    names = []
    kwargs = {}
    while True:
        resp = cgp.list_profiling_groups(**kwargs)
        names.extend(resp.get("profilingGroupNames", []))
        nxt = resp.get("nextToken")
        if not nxt:
            break
        kwargs["nextToken"] = nxt
    assert names.count(name) == 1, f"expected exactly 1 profiling group named {name!r}, found {names.count(name)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
