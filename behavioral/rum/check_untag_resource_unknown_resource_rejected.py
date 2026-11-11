"""untag-resource-unknown-resource-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-unknown-resource-rejected"
GROUP = "error-semantics"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource on a nonexistent app monitor ARN is rejected with NotFoundException and a malformed
    ARN with BadRequestException (exact messages), while the same call on an existing tagged app monitor
    removes the tag."""
    rum = ctx.client("rum")

    # An app monitor name that was never created: RUM's UntagResource DOES
    # verify the target resource exists and rejects with NotFoundException.
    ghost_name = ctx.unique_name("sim2real-rum-ghost-")
    ghost_arn = _app_monitor_arn(ctx, ghost_name)
    err = _client_error(lambda: rum.untag_resource(ResourceArn=ghost_arn, TagKeys=["Environment"]))
    assert err["Code"] == "NotFoundException", repr(err)
    expected_message = "Resource was not found"
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Boundary: a structurally malformed ARN (missing the required "arn:...:"
    # shape) is rejected as a validation failure, distinct from the
    # not-found rejection above -- a syntax check, not an existence check.
    err = _client_error(lambda: rum.untag_resource(ResourceArn="not-an-arn-at-all", TagKeys=["Environment"]))
    assert err["Code"] == "BadRequestException", repr(err)
    expected_message = "Invalid input resource arn: bad syntax"
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Positive control: a real, tagged app monitor's tag is actually removed.
    name = ctx.unique_name("sim2real-rum-untag-")
    rum.create_app_monitor(Name=name, Domain="localhost")
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=name))
    arn = _app_monitor_arn(ctx, name)
    rum.tag_resource(ResourceArn=arn, Tags={"Environment": "staging"})
    before = rum.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert before.get("Environment") == "staging", repr(before)

    rum.untag_resource(ResourceArn=arn, TagKeys=["Environment"])
    after = rum.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert "Environment" not in after, repr(after)


def _client_error(fn) -> dict:
    """Call fn(); return the botocore Error dict (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _app_monitor_arn(ctx, name: str) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:rum:{ctx.region}:{account_id}:appmonitor/{name}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
