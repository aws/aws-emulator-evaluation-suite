"""list-profiling-groups-reflects-lifecycle."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "list-profiling-groups-reflects-lifecycle"
GROUP = "listing"
SERVICES = ["codeguruprofiler"]


def _poll_membership(cgp, name, present, timeout_s=30.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    names = []
    while time.monotonic() < deadline:
        names = [
            pg["name"]
            for pg in cgp.list_profiling_groups(includeDescription=True, maxResults=1000)[
                "profilingGroups"
            ]
        ]
        if (name in names) == present:
            return names
        time.sleep(interval_s)
    raise AssertionError(f"ListProfilingGroups membership for {name} never reached present={present}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created profiling group appears in ListProfilingGroups (with matching
    computePlatform in the includeDescription=True view) and disappears once deleted."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-")

    cgp.create_profiling_group(
        profilingGroupName=name, clientToken=str(uuid.uuid4()), computePlatform="AWSLambda"
    )
    deleted = False

    def _cleanup():
        if not deleted:
            cgp.delete_profiling_group(profilingGroupName=name)

    ctx.on_cleanup(_cleanup)

    _poll_membership(cgp, name, True)
    listed = cgp.list_profiling_groups(includeDescription=True, maxResults=1000)["profilingGroups"]
    match = next(g for g in listed if g["name"] == name)
    assert match["computePlatform"] == "AWSLambda", (
        f"expected computePlatform=AWSLambda in ListProfilingGroups, got {match['computePlatform']!r}"
    )

    cgp.delete_profiling_group(profilingGroupName=name)
    deleted = True
    _poll_membership(cgp, name, False)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
