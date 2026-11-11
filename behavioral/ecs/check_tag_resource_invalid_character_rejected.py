"""tag-resource-invalid-character-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-invalid-character-rejected"
GROUP = "state-machine"
SERVICES = ["ecs"]


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, because an emulator accepting input real AWS refuses must fail loudly rather than
    read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with an emoji in a tag value fails with InvalidParameterException and its exact message
    and the tag is not stored, while a plain-ASCII tag on the same cluster is stored.
    """
    ecs = ctx.client("ecs")
    cluster_name = ctx.unique_name("sim2real-cluster-tagbad-")

    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    # Positive control: a plain-ASCII tag value is accepted.
    ok_key = "sim2real-tagbad-ok"
    ecs.tag_resource(resourceArn=cluster_arn, tags=[{"key": ok_key, "value": "production"}])
    control_tags = ecs.list_tags_for_resource(resourceArn=cluster_arn)["tags"]
    assert any(t["key"] == ok_key and t["value"] == "production" for t in control_tags), (
        f"positive control failed: expected tag {ok_key!r}='production' present, got {control_tags}"
    )

    # Negative: a tag value containing an emoji must be rejected.
    bad_key = "sim2real-tagbad-invalid"
    code, message = _error(
        lambda: ecs.tag_resource(resourceArn=cluster_arn, tags=[{"key": bad_key, "value": "prod-\U0001F389"}])
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for a tag value with a disallowed character, got {code!r}"
    )
    assert message == (
        "Some tags contain invalid characters. "
        "Valid characters: UTF-8 letters, spaces, numbers and _ . / = + - : @."
    ), message

    post_tags = ecs.list_tags_for_resource(resourceArn=cluster_arn)["tags"]
    assert not any(t["key"] == bad_key for t in post_tags), (
        f"rejected tag {bad_key!r} must not be persisted, but found it in {post_tags}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
