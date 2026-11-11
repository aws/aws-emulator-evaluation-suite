"""op-contract-tag-resource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-tag-resource"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adds a tag that ListTagsForResource returns, while TagResource and
    ListTagsForResource on a nonexistent task-definition ARN are both refused ClientException
    'Unable to describe task definition.'."""
    ecs = ctx.client("ecs")
    sts = ctx.client("sts")

    cluster_name = ctx.unique_name("sim2real-ecs-tagres-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    # A cluster that was just created may not yet be visible to TagResource on every
    # backend replica; retry past the transient ClusterNotFoundException instead of
    # treating it as the resource-not-found contract under test.
    _retry_until_not_found_clears(lambda: ecs.tag_resource(
        resourceArn=cluster_arn, tags=[{"key": "sim2real-env", "value": "test"}]
    ))
    tag_list = ecs.list_tags_for_resource(resourceArn=cluster_arn)["tags"]
    assert {"key": "sim2real-env", "value": "test"} in tag_list, tag_list

    account_id = sts.get_caller_identity()["Account"]
    bogus_td_arn = (
        f"arn:aws:ecs:{ctx.region}:{account_id}:task-definition/sim2real-nonexistent-family-8814:1"
    )
    # Real ECS rejects tagging of a well-formed but nonexistent task-definition ARN with the
    # generic ClientException, not ResourceNotFoundException.
    code, message = _error(lambda: ecs.tag_resource(
        resourceArn=bogus_td_arn, tags=[{"key": "sim2real-env", "value": "test"}]
    ))
    assert code == "ClientException", f"expected ClientException, got {code!r}"
    assert message == "Unable to describe task definition.", message

    # Effect absent: an independent read of the same bogus ARN also fails, so the rejected
    # call recorded no tag anywhere for it.
    list_code, list_message = _error(lambda: ecs.list_tags_for_resource(resourceArn=bogus_td_arn))
    assert list_code == "ClientException", f"expected ClientException, got {list_code!r}"
    assert list_message == "Unable to describe task definition.", list_message


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


def _retry_until_not_found_clears(fn, timeout=30.0, interval=1.0):
    import time
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout
    while True:
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] != "ClusterNotFoundException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
