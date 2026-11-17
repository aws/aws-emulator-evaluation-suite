"""delete-api-twice-not-idempotent-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-api-twice-not-idempotent-not-found"
GROUP = "overly-permissive"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn):
    """Call fn; return the ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second DeleteApi on an already-deleted ApiId fails NotFoundException rather than
    succeeding again as a no-op, while a fresh API's first DeleteApi still succeeds."""
    agw = ctx.client("apigatewayv2")

    deleted_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-dd-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: agw.delete_api(ApiId=deleted_id)))
    agw.delete_api(ApiId=deleted_id)

    code, message = _error(lambda: agw.delete_api(ApiId=deleted_id))
    assert code == "NotFoundException", (
        f"expected NotFoundException for a second DeleteApi, got {code}: {message!r}"
    )
    assert message == f"Invalid API identifier specified {ctx.account}:{deleted_id}", (
        f"expected the exact invalid-API-identifier message for {deleted_id}, got {message!r}"
    )
    remaining_ids = [item["ApiId"] for item in agw.get_apis().get("Items", [])]
    assert deleted_id not in remaining_ids, (
        f"the double-deleted api {deleted_id!r} must not have been resurrected"
    )

    # Positive control: a fresh API's first DeleteApi still succeeds, so the rejection above
    # is about the dead id, not about DeleteApi being universally denied.
    live_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-dd-control-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: agw.delete_api(ApiId=live_id)))
    agw.delete_api(ApiId=live_id)
    still_gone_code, still_gone_message = _error(lambda: agw.get_api(ApiId=live_id))
    assert still_gone_code == "NotFoundException", (
        f"expected the control API to be gone after its own delete, got {still_gone_code}: {still_gone_message!r}"
    )


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
