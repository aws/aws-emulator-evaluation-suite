"""untag-resource-partial-key-removal-preserves-others."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "untag-resource-partial-key-removal-preserves-others"
GROUP = "state"
SERVICES = ["detective"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """Removing one tag key via UntagResource must leave the other tags on the same
    resource intact -- untagging is scoped to the given TagKeys only."""
    d = ctx.client("detective")
    arn = d.create_graph()["GraphArn"]
    # NOTE: an account can administer only one behavior graph per Region, so this graph is
    # shared with other checks in the suite run; it is intentionally not deleted here.

    d.tag_resource(ResourceArn=arn, Tags={"sim2real-detective-a": "1", "sim2real-detective-b": "2"})
    _poll_until(
        probe=lambda: d.list_tags_for_resource(ResourceArn=arn)["Tags"],
        predicate=lambda t: t.get("sim2real-detective-a") == "1" and t.get("sim2real-detective-b") == "2",
        timeout_s=30.0,
        interval_s=2.0,
    )

    d.untag_resource(ResourceArn=arn, TagKeys=["sim2real-detective-a"])

    final = _poll_until(
        probe=lambda: d.list_tags_for_resource(ResourceArn=arn)["Tags"],
        predicate=lambda t: "sim2real-detective-a" not in t,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert final.get("sim2real-detective-b") == "2", f"unexpected tags: {final!r}"
    assert "sim2real-detective-a" not in final, f"expected key removed, still present in {final!r}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
