"""get-tags-on-deleted-api-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-tags-on-deleted-api-not-found"
GROUP = "tagging"
SERVICES = ["apigatewayv2"]


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTags on a tagged API's ARN after DeleteApi fails NotFoundException, not an empty tag
    map, while the same read against a sibling API's ARN still returns its tags."""
    agw = ctx.client("apigatewayv2")

    dead = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-gtdead-"),
        ProtocolType="HTTP",
        Tags={"k": "v"},
    )
    dead_id = dead["ApiId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: agw.delete_api(ApiId=dead_id)))
    dead_arn = f"arn:aws:apigateway:{ctx.region}::/apis/{dead_id}"

    before = agw.get_tags(ResourceArn=dead_arn)["Tags"]
    assert before == {"k": "v"}, f"GetTags on the live API before delete: expected {{'k': 'v'}}, got {before!r}"

    agw.delete_api(ApiId=dead_id)

    code, message = _error(lambda: agw.get_tags(ResourceArn=dead_arn))
    assert code == "NotFoundException", (
        f"GetTags on a deleted API's ARN: expected NotFoundException, got {code}: {message!r}"
    )
    expected = "Resource was not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: a sibling API created and tagged at the same time is unaffected.
    sibling = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-gtlive-"),
        ProtocolType="HTTP",
        Tags={"k": "v"},
    )
    sibling_id = sibling["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=sibling_id))
    sibling_arn = f"arn:aws:apigateway:{ctx.region}::/apis/{sibling_id}"
    sibling_tags = agw.get_tags(ResourceArn=sibling_arn)["Tags"]
    assert sibling_tags == {"k": "v"}, (
        f"GetTags on the live sibling API: expected {{'k': 'v'}}, got {sibling_tags!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
