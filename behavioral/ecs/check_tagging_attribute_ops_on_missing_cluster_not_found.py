"""tagging-attribute-ops-on-missing-cluster-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tagging-attribute-ops-on-missing-cluster-not-found"
GROUP = 'error-semantics'
SERVICES = ['ecs']


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected ClusterNotFoundException, but the call SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource, UntagResource, ListTagsForResource, DeleteAttributes and ListAttributes on a
    nonexistent cluster return ClusterNotFoundException, while on a real cluster the same calls
    work (DeleteAttributes on an unknown target there is not ClusterNotFoundException)."""
    ecs = ctx.client("ecs")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    real_cluster_name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    real_cluster_arn = ecs.create_cluster(
        clusterName=real_cluster_name, tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=real_cluster_arn))

    # ---- positive control: the identical five operations succeed against the real cluster ----
    ecs.tag_resource(resourceArn=real_cluster_arn, tags=[{"key": "k", "value": "v"}])
    tags_after_tag = {
        t["key"]: t["value"] for t in ecs.list_tags_for_resource(resourceArn=real_cluster_arn)["tags"]
    }
    assert tags_after_tag.get("k") == "v", f"TagResource control: tag not visible, got {tags_after_tag}"

    ecs.untag_resource(resourceArn=real_cluster_arn, tagKeys=["k"])
    tags_after_untag = {
        t["key"]: t["value"] for t in ecs.list_tags_for_resource(resourceArn=real_cluster_arn)["tags"]
    }
    assert "k" not in tags_after_untag, f"UntagResource control: tag still present, got {tags_after_untag}"

    # No container instance is registered (that needs a signed EC2 identity document), but
    # ListAttributes must still succeed on the empty cluster.
    listed = ecs.list_attributes(cluster=real_cluster_arn, targetType="container-instance")
    assert listed["attributes"] == [], f"ListAttributes control: expected none yet, got {listed}"

    # The cluster is validated before the target, so a missing target inside a real cluster must
    # not yield ClusterNotFoundException.
    real_target_arn = (
        f"arn:aws:ecs:{ctx.region}:{account_id}:container-instance/{real_cluster_name}/"
        "11111111111111111111111111111111"
    )
    code = None
    try:
        ecs.delete_attributes(
            cluster=real_cluster_arn, attributes=[{"name": "x", "targetId": real_target_arn}]
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
    assert code != "ClusterNotFoundException", (
        f"DeleteAttributes control: a REAL cluster returned ClusterNotFoundException (got {code!r})"
    )

    # ---- negative: the same five operations against a cluster that was never created ----
    bogus_cluster = real_cluster_name + "-absent"
    bogus_cluster_arn = f"arn:aws:ecs:{ctx.region}:{account_id}:cluster/{bogus_cluster}"
    fake_ci_arn = (
        f"arn:aws:ecs:{ctx.region}:{account_id}:container-instance/{bogus_cluster}/"
        "00000000000000000000000000000000"
    )

    not_found = ("ClusterNotFoundException", "Cluster not found.")

    error = _error(
        lambda: ecs.tag_resource(resourceArn=bogus_cluster_arn, tags=[{"key": "k", "value": "v"}])
    )
    assert error == not_found, f"TagResource: got {error!r}"

    error = _error(lambda: ecs.untag_resource(resourceArn=bogus_cluster_arn, tagKeys=["k"]))
    assert error == not_found, f"UntagResource: got {error!r}"

    error = _error(lambda: ecs.list_tags_for_resource(resourceArn=bogus_cluster_arn))
    assert error == not_found, f"ListTagsForResource: got {error!r}"

    error = _error(
        lambda: ecs.delete_attributes(
            cluster=bogus_cluster, attributes=[{"name": "x", "targetId": fake_ci_arn}]
        )
    )
    assert error == not_found, f"DeleteAttributes: got {error!r}"

    error = _error(
        lambda: ecs.list_attributes(cluster=bogus_cluster, targetType="container-instance")
    )
    assert error == not_found, f"ListAttributes: got {error!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
