"""tag-resource-overwrite-and-absent-key-untag-exact-set."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-overwrite-and-absent-key-untag-exact-set"
GROUP = "tagging"
SERVICES = ["ecs"]


def _retry_until_not_found_clears(fn, timeout_s: float = 30.0, interval_s: float = 1.0):
    """Retry fn() past the transient ClusterNotFoundException a just-created cluster can
    show before it is visible to TagResource; any other error or a timeout raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource overwrites an existing key's value in place, keeping the tag count the
    same, and UntagResource of a key already absent succeeds and leaves the set unchanged.
    """
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-tagset-")
    cluster = ecs.create_cluster(clusterName=name)["cluster"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=name))
    arn = cluster["clusterArn"]

    _retry_until_not_found_clears(lambda: ecs.tag_resource(
        resourceArn=arn,
        tags=[
            {"key": "sim2real-env", "value": "dev"},
            {"key": "sim2real-team", "value": "alpha"},
        ],
    ))
    after_first = {t["key"]: t["value"] for t in ecs.list_tags_for_resource(resourceArn=arn)["tags"]}
    assert after_first == {"sim2real-env": "dev", "sim2real-team": "alpha"}, (
        f"expected exactly the 2 tags just applied, got {after_first!r}"
    )

    ecs.tag_resource(resourceArn=arn, tags=[{"key": "sim2real-env", "value": "prod"}])
    after_overwrite = {t["key"]: t["value"] for t in ecs.list_tags_for_resource(resourceArn=arn)["tags"]}
    assert after_overwrite == {"sim2real-env": "prod", "sim2real-team": "alpha"}, (
        f"expected the existing key overwritten in place, still exactly 2 pairs, got {after_overwrite!r}"
    )

    ecs.untag_resource(resourceArn=arn, tagKeys=["sim2real-team"])
    after_untag = {t["key"]: t["value"] for t in ecs.list_tags_for_resource(resourceArn=arn)["tags"]}
    assert after_untag == {"sim2real-env": "prod"}, (
        f"expected exactly the other pair to remain, got {after_untag!r}"
    )

    ecs.untag_resource(resourceArn=arn, tagKeys=["sim2real-team"])
    after_absent_untag = {t["key"]: t["value"] for t in ecs.list_tags_for_resource(resourceArn=arn)["tags"]}
    assert after_absent_untag == {"sim2real-env": "prod"}, (
        f"untagging an already-absent key must leave the set unchanged, got {after_absent_untag!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
