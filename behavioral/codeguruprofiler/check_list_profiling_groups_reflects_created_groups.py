"""list-profiling-groups-reflects-created-groups."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "list-profiling-groups-reflects-created-groups"
GROUP = "control-plane"
SERVICES = ["codeguruprofiler"]


def _create(ctx, cgp, name):
    token = str(uuid.uuid4())
    cgp.create_profiling_group(
        profilingGroupName=name,
        clientToken=token,
        agentOrchestrationConfig={"profilingEnabled": False},
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))


def _list_all_names(cgp):
    names = []
    kwargs = {"includeDescription": True}
    while True:
        resp = cgp.list_profiling_groups(**kwargs)
        names.extend(pg["name"] for pg in resp.get("profilingGroups", []))
        token = resp.get("nextToken")
        if not token:
            return names
        kwargs["nextToken"] = token


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListProfilingGroups (with includeDescription) enumerates newly created groups."""
    cgp = ctx.client("codeguruprofiler")
    name_a = ctx.unique_name("sim2real-cgp-list-a-")
    name_b = ctx.unique_name("sim2real-cgp-list-b-")
    _create(ctx, cgp, name_a)
    _create(ctx, cgp, name_b)

    names = _list_all_names(cgp)
    assert name_a in names, f"{name_a} missing from ListProfilingGroups output"
    assert name_b in names, f"{name_b} missing from ListProfilingGroups output"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
