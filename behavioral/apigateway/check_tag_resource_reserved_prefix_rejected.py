"""tag-resource-reserved-prefix-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-reserved-prefix-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a tag key that starts with the reserved 'aws:' prefix with
    BadRequestException, and the reserved tag is never created; a normal tag key applied in
    the same call batch (positive control) is written successfully and visible via GetTags."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-apigw-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    resource_arn = _rest_api_arn(ctx, api_id)

    # Positive control: an ordinary tag key succeeds.
    apigw.tag_resource(resourceArn=resource_arn, tags={"Team": "platform"})
    after_control = apigw.get_tags(resourceArn=resource_arn)["tags"]
    assert after_control.get("Team") == "platform", (
        f"expected positive-control tag Team=platform, got {after_control!r}"
    )

    # Negative: a tag key with the reserved "aws:" prefix is rejected outright.
    err = _client_error(
        lambda: apigw.tag_resource(resourceArn=resource_arn, tags={"aws:Reserved": "nope"})
    )
    assert err.get("Code") == "BadRequestException", f"expected BadRequestException, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid tag key. Tag keys cannot start with 'aws:' (case insensitive)", (
        f"expected the exact reserved-prefix refusal message, got {err.get('Message')!r}"
    )

    after_rejected = apigw.get_tags(resourceArn=resource_arn)["tags"]
    assert "aws:Reserved" not in after_rejected, "reserved-prefixed tag must never be stored"
    assert after_rejected == {"Team": "platform"}, "rejected call must not disturb existing tags"


def _rest_api_arn(ctx, api_id):
    partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
    return f"arn:{partition}:apigateway:{ctx.region}::/restapis/{api_id}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
