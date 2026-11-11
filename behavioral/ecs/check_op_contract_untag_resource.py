"""op-contract-untag-resource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-untag-resource"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the named keys, leaving other tags intact; calling it
    against a well-formed but nonexistent cluster ARN is rejected with ClusterNotFoundException
    and the resource's real tags are left untouched."""
    ecs = ctx.client("ecs")
    sts = ctx.client("sts")

    cluster_name = ctx.unique_name("sim2real-ecs-untagres-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    ecs.tag_resource(resourceArn=cluster_arn, tags=[
        {"key": "sim2real-keep", "value": "yes"},
        {"key": "sim2real-drop", "value": "yes"},
    ])
    ecs.untag_resource(resourceArn=cluster_arn, tagKeys=["sim2real-drop"])

    tag_list = ecs.list_tags_for_resource(resourceArn=cluster_arn)["tags"]
    assert {"key": "sim2real-keep", "value": "yes"} in tag_list, tag_list
    assert not any(t["key"] == "sim2real-drop" for t in tag_list), tag_list

    account_id = sts.get_caller_identity()["Account"]
    bogus_cluster_arn = f"arn:aws:ecs:{ctx.region}:{account_id}:cluster/sim2real-nonexistent-cluster-6642"
    code, message = _error(lambda: ecs.untag_resource(
        resourceArn=bogus_cluster_arn, tagKeys=["sim2real-keep"]
    ))
    assert code == "ClusterNotFoundException", code
    assert message == "Cluster not found.", message

    # The real resource's tags are unaffected by the rejected call.
    tag_list_after = ecs.list_tags_for_resource(resourceArn=cluster_arn)["tags"]
    assert {"key": "sim2real-keep", "value": "yes"} in tag_list_after, tag_list_after


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, because an emulator accepting input real AWS refuses must fail loudly rather than
    read as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
