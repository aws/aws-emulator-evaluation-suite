"""untag-resource-nonexistent-api-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-nonexistent-api-not-found"
GROUP = "tagging"
SERVICES = ["apigatewayv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UntagResource on an API ARN that was deleted fails NotFoundException and leaves the tags
    of a still-existing API untouched, while the identical call on that real API succeeds."""
    agw = ctx.client("apigatewayv2")

    live = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-untagnf-live-"), ProtocolType="HTTP", Tags={"k": "v"}
    )
    live_id = live["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=live_id))
    live_arn = f"arn:aws:apigateway:{ctx.region}::/apis/{live_id}"

    doomed = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-untagnf-dead-"), ProtocolType="HTTP", Tags={"k": "v"}
    )
    doomed_id = doomed["ApiId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: agw.delete_api(ApiId=doomed_id)))
    doomed_arn = f"arn:aws:apigateway:{ctx.region}::/apis/{doomed_id}"
    agw.delete_api(ApiId=doomed_id)

    code, message = _error(lambda: agw.untag_resource(ResourceArn=doomed_arn, TagKeys=["k"]))
    assert code == "NotFoundException", (
        f"UntagResource on a deleted API: expected NotFoundException, got {code}: {message!r}"
    )
    assert message == "Resource was not found", (
        f"UntagResource on a deleted API: unexpected message {message!r}"
    )

    # effect absent: the live API's tags are untouched by the refused call on the dead one.
    unaffected = agw.get_tags(ResourceArn=live_arn).get("Tags", {})
    assert unaffected.get("k") == "v", (
        f"the live API's tags changed after a refused UntagResource on an unrelated API: {unaffected!r}"
    )

    # positive control: the identical call on the live API succeeds.
    agw.untag_resource(ResourceArn=live_arn, TagKeys=["k"])
    after = agw.get_tags(ResourceArn=live_arn).get("Tags", {})
    assert "k" not in after, f"UntagResource on the live API did not remove the tag: {after!r}"


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
