"""neptune-graph-tag-resource-lifecycle-roundtrip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "neptune-graph-tag-resource-lifecycle-roundtrip"
GROUP = "control-plane"
SERVICES = ["neptune-graph"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new graph has no tags; after TagResource, ListTagsForResource returns exactly the added tag, and
    after UntagResource it returns none."""
    ng = ctx.client("neptune-graph")
    graph_id = _create_available_graph(ctx, ng)
    graph_arn = ng.get_graph(graphIdentifier=graph_id)["arn"]

    initial_tags = ng.list_tags_for_resource(resourceArn=graph_arn)["tags"]
    assert initial_tags == {}, f"expected no tags on a freshly created graph, got {initial_tags}"

    ng.tag_resource(resourceArn=graph_arn, tags={"sim2real-owner": "behavioral-check"})
    after_tag = ng.list_tags_for_resource(resourceArn=graph_arn)["tags"]
    expected_tag = {"sim2real-owner": "behavioral-check"}
    assert after_tag == expected_tag, f"expected {expected_tag} after tag_resource, got {after_tag}"

    ng.untag_resource(resourceArn=graph_arn, tagKeys=["sim2real-owner"])
    after_untag = ng.list_tags_for_resource(resourceArn=graph_arn)["tags"]
    assert after_untag == {}, f"expected no tags after untag_resource, got {after_untag}"


# ===== helpers =====
def _poll_until(probe, predicate, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_available_graph(ctx, ng, memory=16, deletion_protection=False):
    name = ctx.unique_name("sim2real-ng-")
    graph_id = ng.create_graph(
        graphName=name,
        provisionedMemory=memory,
        deletionProtection=deletion_protection,
        publicConnectivity=False,
    )["id"]

    def _cleanup():
        def _settle(timeout_s):
            return _poll_until(
                lambda: ng.get_graph(graphIdentifier=graph_id),
                lambda g: g["status"] in ("AVAILABLE", "FAILED", "STOPPED"),
                timeout_s=timeout_s,
                interval_s=2,
            )

        try:
            if _settle(900).get("deletionProtection"):
                ng.update_graph(graphIdentifier=graph_id, deletionProtection=False)
                _settle(120)
            ng.delete_graph(graphIdentifier=graph_id, skipSnapshot=True)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    status = _poll_until(
        lambda: ng.get_graph(graphIdentifier=graph_id)["status"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=900,
        interval_s=15,
    )
    if status != "AVAILABLE":
        raise AssertionError(f"graph {graph_id} did not reach AVAILABLE, got {status}")
    return graph_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
