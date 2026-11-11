"""list-tags-for-resource-reflects-tags-set-at-create-time."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-resource-reflects-tags-set-at-create-time"
GROUP = "control-plane"
SERVICES = ["neptune-graph"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag passed to CreateGraph is returned by ListTagsForResource once the graph is AVAILABLE, with no
    TagResource call."""
    ng = ctx.client("neptune-graph")
    name = ctx.unique_name("sim2real-ng-")
    resp = ng.create_graph(
        graphName=name,
        provisionedMemory=16,
        publicConnectivity=False,
        tags={"sim2real-created-at": "create-time"},
    )
    graph_id = resp["id"]
    arn = resp["arn"]

    def _cleanup() -> None:
        def _settle(timeout_s):
            return _poll_until(
                lambda: ng.get_graph(graphIdentifier=graph_id),
                lambda g: g["status"] not in ("CREATING", "UPDATING"),
                timeout_s=timeout_s,
                interval_s=2,
            )

        try:
            if _settle(1200).get("deletionProtection"):
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
        timeout_s=1500,
        interval_s=15,
    )
    assert status == "AVAILABLE", f"expected graph {graph_id} AVAILABLE, got {status!r}"

    tags = ng.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags.get("sim2real-created-at") == "create-time", (
        f"expected ListTagsForResource to reflect the create-time tag, got {tags!r}"
    )


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
