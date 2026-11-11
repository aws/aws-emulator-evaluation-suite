"""tag-nonexistent-resource-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-nonexistent-resource-fails"
GROUP = 'overly-permissive'
SERVICES = ['ecs']

_TAGS = [{"key": "sim2real:check", "value": CHECK}]


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource and ListTagsForResource on a cluster ARN in a foreign account fail with
    InvalidParameterException "The ARN provided is invalid.", while TagResource on the caller's own
    cluster lands and is listed.
    """
    ecs = ctx.client("ecs")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    real_cluster_arn = ecs.create_cluster(
        clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"), tags=_TAGS
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=real_cluster_arn))

    # Break exactly one thing: same ARN shape, an account that is never the caller's.
    foreign_account_id = "111111111111" if account_id != "111111111111" else "222222222222"
    foreign_arn = real_cluster_arn.replace(f":{account_id}:", f":{foreign_account_id}:")

    code, message = _error(
        lambda: ecs.tag_resource(resourceArn=foreign_arn, tags=[{"key": "a", "value": "b"}])
    )
    assert code == "InvalidParameterException", f"TagResource cross-account ARN: got {code}"
    assert message == "The ARN provided is invalid.", f"TagResource cross-account ARN: unexpected message {message!r}"

    read_code, read_message = _error(lambda: ecs.list_tags_for_resource(resourceArn=foreign_arn))
    assert read_code == "InvalidParameterException", (
        f"effect-absent read after the rejected TagResource: got {read_code}"
    )
    assert read_message == "The ARN provided is invalid.", (
        f"effect-absent read after the rejected TagResource: unexpected message {read_message!r}"
    )

    # Positive control: the identical call shape against a cluster the caller
    # really owns succeeds, so the rejection above is not a blanket failure.
    ecs.tag_resource(resourceArn=real_cluster_arn, tags=[{"key": "a", "value": "b"}])
    own_tags = {
        t["key"]: t["value"]
        for t in ecs.list_tags_for_resource(resourceArn=real_cluster_arn)["tags"]
    }
    assert own_tags.get("a") == "b", f"positive control: tag did not land, got {own_tags}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
