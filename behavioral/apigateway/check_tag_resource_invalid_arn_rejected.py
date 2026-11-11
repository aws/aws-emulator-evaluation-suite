"""tag-resource-invalid-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-invalid-arn-rejected"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    over-permissive target accepting input real AWS refuses must not be reported as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource, UntagResource and GetTags succeed on a real resource (positive control), reject a
    non-ARN resourceArn with BadRequestException and fail with NotFoundException for a well-formed
    nonexistent one, where GetTags fabricates no empty success."""
    ag = ctx.client("apigateway")

    api_id = ag.create_rest_api(name=ctx.unique_name("sim2real-behav-apigw-"))["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    real_arn = f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}"

    ag.tag_resource(resourceArn=real_arn, tags={"sim2real-env": "x"})
    tagged = ag.get_tags(resourceArn=real_arn)["tags"]
    assert tagged.get("sim2real-env") == "x", (
        f"positive control: expected tag visible via GetTags on a real resourceArn, got {tagged}"
    )
    ag.untag_resource(resourceArn=real_arn, tagKeys=["sim2real-env"])
    untagged = ag.get_tags(resourceArn=real_arn)["tags"]
    assert "sim2real-env" not in untagged, (
        f"positive control: expected tag removed via UntagResource on a real resourceArn, got {untagged}"
    )

    malformed_arn = "sim2real-behav-not-an-arn"
    err = _client_error(
        lambda: ag.tag_resource(resourceArn=malformed_arn, tags={"sim2real-env": "x"})
    )
    assert err.get("Code") == "BadRequestException", (
        f"expected BadRequestException tagging a malformed (non-ARN) resourceArn, got {err.get('Code')!r}"
    )
    assert err.get("Message") == "Invalid ARN specified in the request", (
        f"expected the exact malformed-ARN refusal message, got {err.get('Message')!r}"
    )

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    missing_id = "sim2realNOTFOUND"
    nonexistent_arn = f"arn:aws:apigateway:{ctx.region}::/restapis/{missing_id}"
    not_found_message = f"Invalid API identifier specified {account_id}:{missing_id}"

    err_tag = _client_error(
        lambda: ag.tag_resource(resourceArn=nonexistent_arn, tags={"sim2real-env": "x"})
    )
    assert err_tag.get("Code") == "NotFoundException", (
        f"expected NotFoundException tagging a well-formed but nonexistent resourceArn, got {err_tag.get('Code')!r}"
    )
    assert err_tag.get("Message") == not_found_message, (
        f"expected {not_found_message!r} tagging a nonexistent resourceArn, got {err_tag.get('Message')!r}"
    )

    err_get = _client_error(lambda: ag.get_tags(resourceArn=nonexistent_arn))
    assert err_get.get("Code") == "NotFoundException", (
        f"GetTags must not fabricate an empty-tags success for an unknown resourceArn, got {err_get.get('Code')!r}"
    )
    assert err_get.get("Message") == not_found_message, (
        f"expected {not_found_message!r} from GetTags on a nonexistent resourceArn, got {err_get.get('Message')!r}"
    )

    err_untag = _client_error(
        lambda: ag.untag_resource(resourceArn=nonexistent_arn, tagKeys=["sim2real-env"])
    )
    assert err_untag.get("Code") == "NotFoundException", (
        f"expected NotFoundException untagging a well-formed but nonexistent resourceArn, got {err_untag.get('Code')!r}"
    )
    assert err_untag.get("Message") == not_found_message, (
        f"expected {not_found_message!r} untagging a nonexistent resourceArn, got {err_untag.get('Message')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
