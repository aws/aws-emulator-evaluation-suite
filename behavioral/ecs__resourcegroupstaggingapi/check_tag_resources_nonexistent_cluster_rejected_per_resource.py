"""tag-resources-nonexistent-cluster-rejected-per-resource."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-resources-nonexistent-cluster-rejected-per-resource"
GROUP = "overly-permissive"
SERVICES = ["ecs", "resourcegroupstaggingapi"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A TagResources batch of one live and one absent ECS cluster tags the live one and reports
    only the absent one in FailedResourcesMap with ECS's ClusterNotFoundException (400) --
    a partial failure, never silently accepted and never a whole-batch failure.
    """
    ecs = ctx.client("ecs")
    rgt = ctx.client("resourcegroupstaggingapi")
    sts = ctx.client("sts")

    account = sts.get_caller_identity()["Account"]
    key = ctx.unique_name("sim2real-behav-part-")

    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    live_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real", "value": CHECK}],
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    ghost_arn = f"arn:aws:ecs:{ctx.region}:{account}:cluster/{ctx.unique_name('sim2real-behav-ghost-')}"

    result = rgt.tag_resources(ResourceARNList=[live_arn, ghost_arn], Tags={key: "partial"})

    failed = result["FailedResourcesMap"]
    assert set(failed) == {ghost_arn}, (
        f"FailedResourcesMap named {sorted(failed)!r}, expected exactly the absent cluster "
        f"{ghost_arn!r} -- the live cluster {live_arn!r} must not fail and the absent one must not pass"
    )
    detail = failed[ghost_arn]
    assert detail["ErrorCode"] == "ClusterNotFoundException", (
        f"the per-resource ErrorCode for an absent cluster was {detail['ErrorCode']!r}, "
        f"expected ECS's own ClusterNotFoundException"
    )
    assert detail["StatusCode"] == 400, (
        f"the per-resource StatusCode was {detail['StatusCode']!r}, expected 400"
    )
    expected = "Cluster not found."
    assert detail["ErrorMessage"] == expected, (
        f"the per-resource ErrorMessage for an absent cluster was {detail['ErrorMessage']!r}, "
        f"expected {expected!r}"
    )

    native_tags = _poll_until(
        lambda: {t["key"]: t["value"] for t in ecs.list_tags_for_resource(resourceArn=live_arn)["tags"]},
        lambda m: m.get(key) == "partial",
        timeout_s=180.0,
    )
    assert native_tags.get(key) == "partial", (
        f"the live cluster {live_arn!r} never received {key}=partial (saw {native_tags!r}) "
        f"-- a partial failure must still apply the tags that succeeded"
    )


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
