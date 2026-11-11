"""tag-resource-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-resource-round-trip"
GROUP = "state"
SERVICES = ["detective"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """TagResource/UntagResource/ListTagsForResource round-trip on a behavior graph: the
    key under test is absent beforehand, TagResource makes it visible, UntagResource
    removes it."""
    d = ctx.client("detective")
    arn = d.create_graph()["GraphArn"]
    # NOTE: an account can administer only one behavior graph per Region, so this graph is shared
    # with other checks in the suite run; it is intentionally not deleted here. Other checks in this
    # directory tag the same graph and do not all clean up after themselves, so an assertion here
    # must be scoped to this check's own key, never to the full tag set.

    initial = d.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert "sim2real-detective-key" not in initial, f"expected no pre-existing tag, got {initial!r}"

    d.tag_resource(ResourceArn=arn, Tags={"sim2real-detective-key": "v1"})

    tags = _poll_until(
        probe=lambda: d.list_tags_for_resource(ResourceArn=arn)["Tags"],
        predicate=lambda t: t.get("sim2real-detective-key") == "v1",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert tags.get("sim2real-detective-key") == "v1"

    d.untag_resource(ResourceArn=arn, TagKeys=["sim2real-detective-key"])

    final = _poll_until(
        probe=lambda: d.list_tags_for_resource(ResourceArn=arn)["Tags"],
        predicate=lambda t: "sim2real-detective-key" not in t,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert "sim2real-detective-key" not in final, f"expected tag removed, got {final!r}"


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
