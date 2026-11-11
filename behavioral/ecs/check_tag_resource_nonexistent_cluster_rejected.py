"""tag-resource-nonexistent-cluster-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-cluster-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource on a well-formed but nonexistent cluster ARN fails with ClusterNotFoundException.

    The identical call succeeds once a cluster by that name exists.
    """
    ecs = ctx.client("ecs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-nope-")
    arn = f"arn:aws:ecs:{ctx.region}:{account_id}:cluster/{name}"

    # Positive control: TagResource succeeds against a real, different cluster in this
    # account, so the account and credentials are otherwise healthy for the operation.
    control_name = ctx.unique_name("sim2real-tagctl-")
    control_arn = ecs.create_cluster(clusterName=control_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=control_name))
    _retry_until_not_found_clears(lambda: ecs.tag_resource(
        resourceArn=control_arn, tags=[{"key": "sim2real-check", "value": "true"}]
    ))
    control_tags = ecs.list_tags_for_resource(resourceArn=control_arn)["tags"]
    assert {"key": "sim2real-check", "value": "true"} in control_tags, control_tags

    # Break: the target cluster does not exist yet. For a well-formed cluster ARN that
    # doesn't exist, ECS raises the cluster-specific not-found error rather than the generic
    # ResourceNotFoundException.
    code, message = _error(lambda: ecs.tag_resource(
        resourceArn=arn, tags=[{"key": "sim2real-check", "value": "true"}]
    ))
    assert code == "ClusterNotFoundException", f"expected ClusterNotFoundException, got {code}"
    assert message == "Cluster not found.", f"unexpected error message: {message!r}"

    # Effect absent: an independent read confirms nothing by that ARN exists.
    cluster_arns = ecs.list_clusters()["clusterArns"]
    assert arn not in cluster_arns, f"{arn} unexpectedly present: {cluster_arns}"

    # Restore: create the cluster, then the identical call succeeds.
    ecs.create_cluster(clusterName=name)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=name))
    _retry_until_not_found_clears(lambda: ecs.tag_resource(
        resourceArn=arn, tags=[{"key": "sim2real-check", "value": "true"}]
    ))
    tag_list = ecs.list_tags_for_resource(resourceArn=arn)["tags"]
    assert {"key": "sim2real-check", "value": "true"} in tag_list, tag_list


def _error(fn):
    """Return (code, message) of the ClientError *fn* raises; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError("expected TagResource to fail, but it succeeded")


def _retry_until_not_found_clears(fn, timeout=30.0, interval=1.0):
    # A cluster that was just created may not yet be visible to TagResource on every
    # backend replica; retry past the transient ClusterNotFoundException instead of
    # treating it as the not-found contract under test.
    deadline = time.monotonic() + timeout
    while True:
        try:
            return fn()
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "ClusterNotFoundException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
