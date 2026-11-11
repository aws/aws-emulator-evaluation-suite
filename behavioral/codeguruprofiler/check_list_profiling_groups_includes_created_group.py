"""list-profiling-groups-includes-created-group."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-profiling-groups-includes-created-group"
GROUP = "state"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created profiling group shows up in a paginated ListProfilingGroups
    (includeDescription=True) walk, with an ARN matching the CreateProfilingGroup
    response."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-behav-cgp-")
    created = cgp.create_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"env": "sim2real"},
    )["profilingGroup"]
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    found_name = False
    found_description = None
    next_token = None
    for _ in range(200):  # bounded pagination walk
        kwargs = {"includeDescription": True, "maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        page = cgp.list_profiling_groups(**kwargs)
        for group in page.get("profilingGroups", []):
            if group["name"] == name:
                found_name = True
                found_description = group
        next_token = page.get("nextToken")
        if not next_token:
            break

    assert found_name, "created profiling group name missing from ListProfilingGroups"
    assert found_description is not None, (
        f"{name} found in ListProfilingGroups but had no description payload"
    )
    assert found_description["arn"] == created["arn"], (
        f"listed arn {found_description['arn']!r} != created arn {created['arn']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
