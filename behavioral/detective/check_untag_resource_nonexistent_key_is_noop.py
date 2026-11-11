"""untag-resource-nonexistent-key-is-noop."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "untag-resource-nonexistent-key-is-noop"
GROUP = "state"
SERVICES = ["detective"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """UntagResource with a tag key that was never set on the resource succeeds without
    error and leaves existing tags untouched."""
    d = ctx.client("detective")
    arn = d.create_graph()["GraphArn"]
    # NOTE: an account can administer only one behavior graph per Region, so this graph is
    # shared with other checks in the suite run; it is intentionally not deleted here.

    d.tag_resource(ResourceArn=arn, Tags={"sim2real-detective-keep": "keep-me"})
    _poll_until(
        probe=lambda: d.list_tags_for_resource(ResourceArn=arn)["Tags"],
        predicate=lambda t: t.get("sim2real-detective-keep") == "keep-me",
        timeout_s=30.0,
        interval_s=2.0,
    )

    # Must not raise, even though this key was never set.
    d.untag_resource(ResourceArn=arn, TagKeys=["sim2real-detective-never-set"])

    tags = _poll_until(
        probe=lambda: d.list_tags_for_resource(ResourceArn=arn)["Tags"],
        predicate=lambda t: t.get("sim2real-detective-keep") == "keep-me",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert tags.get("sim2real-detective-keep") == "keep-me", f"unexpected tags: {tags!r}"
    assert "sim2real-detective-never-set" not in tags, f"unexpected tags: {tags!r}"


def _delete_graph_quietly(d, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        d.delete_graph(GraphArn=arn)
    except ClientError:
        pass


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
