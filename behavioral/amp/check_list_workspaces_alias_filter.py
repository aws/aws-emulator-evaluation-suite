"""list-workspaces-alias-filter."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-workspaces-alias-filter"
GROUP = "list"
SERVICES = ["amp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListWorkspaces with an `alias` filter returns only the workspace(s) with that exact
    alias, excluding sibling workspaces created in the same run."""
    amp = ctx.client("amp")
    target_alias = ctx.unique_name("sim2real-amp-alias-target-")
    other_alias = ctx.unique_name("sim2real-amp-alias-other-")

    target_id = amp.create_workspace(alias=target_alias, tags={"sim2real-owner": "behavioral"})["workspaceId"]
    ctx.on_cleanup(lambda: amp.delete_workspace(workspaceId=target_id))
    other_id = amp.create_workspace(alias=other_alias, tags={"sim2real-owner": "behavioral"})["workspaceId"]
    ctx.on_cleanup(lambda: amp.delete_workspace(workspaceId=other_id))

    for wid in (target_id, other_id):
        _poll_until(
            lambda wid=wid: amp.describe_workspace(workspaceId=wid)["workspace"]["status"]["statusCode"],
            lambda s: s == "ACTIVE",
            timeout_s=120,
        )

    listed = amp.list_workspaces(alias=target_alias)["workspaces"]
    ids = {w["workspaceId"] for w in listed}
    assert target_id in ids, f"expected {target_id} among alias-filtered results {ids}"
    assert other_id not in ids, f"unfiltered {other_id} leaked into alias-filtered results {ids}"
    mismatched = [w["alias"] for w in listed if w["alias"] != target_alias]
    assert not mismatched, f"alias filter returned entries not matching {target_alias!r}: {mismatched}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
