"""tag-resource-unicode-key-value-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-resource-unicode-key-value-round-trip"
GROUP = "representation"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource preserves unicode tag keys and values byte-identical on ListTagsForResource."""
    ecs = ctx.client("ecs")
    cluster_name = ctx.unique_name("sim2real-behav-ecs-utag-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    tags_in = [
        {"key": "环境", "value": "生产环境-2024"},
        {"key": "Ключ-тест", "value": "Значение_日本語"},
        {"key": "café-naïve", "value": "Zürich Tōkyō"},
    ]

    # A brand-new cluster ARN can trail ECS's own tagging-service propagation by a beat; retry
    # TagResource itself (not just the read) on ClusterNotFoundException within a bounded window
    # rather than treating a transient not-yet-visible resource as a hard failure.
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 30
    while True:
        try:
            ecs.tag_resource(resourceArn=cluster_arn, tags=tags_in)
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "ClusterNotFoundException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)

    returned = None
    deadline = time.monotonic() + 30
    while True:
        try:
            returned = ecs.list_tags_for_resource(resourceArn=cluster_arn)["tags"]
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "ClusterNotFoundException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)

    returned_by_key = {t["key"]: t["value"] for t in returned}
    expected_by_key = {t["key"]: t["value"] for t in tags_in}

    for key, value in expected_by_key.items():
        assert key in returned_by_key, (
            f"unicode tag key {key!r} missing from ListTagsForResource; "
            f"keys present: {sorted(returned_by_key)!r}"
        )
        assert returned_by_key[key] == value, (
            f"unicode tag value changed for {key!r}: {returned_by_key[key]!r} != {value!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

