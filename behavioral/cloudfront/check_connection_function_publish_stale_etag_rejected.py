"""connection-function-publish-stale-etag-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "connection-function-publish-stale-etag-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_CONFIG = {"Comment": "sim2real-behav", "Runtime": "cloudfront-js-2.0"}
_CODE_V1 = b"function connectionHandler(connection) {\n    connection.allow();\n}\n"
_CODE_V2 = b"function connectionHandler(connection) {\n    connection.allow();\n    // v2\n}\n"


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected success raises,
    so a target that accepts what AWS refuses fails as an accepted call, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A superseded If-Match on PublishConnectionFunction fails with PreconditionFailed and leaves
    the function in DEVELOPMENT; a never-issued If-Match fails with InvalidIfMatchVersion instead;
    the identical publish then succeeds and promotes the function to LIVE.
    """
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-connfn-pubstale-")[:64]

    created = cf.create_connection_function(
        Name=name,
        ConnectionFunctionConfig=_CONFIG,
        ConnectionFunctionCode=_CODE_V1,
        Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
    )
    fn_id = created["ConnectionFunctionSummary"]["Id"]
    stale_etag = created["ETag"]

    def _cleanup():
        try:
            etag = cf.describe_connection_function(Identifier=fn_id)["ETag"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "EntityNotFound":
                return
            raise
        cf.delete_connection_function(Id=fn_id, IfMatch=etag)

    ctx.on_cleanup(_cleanup)

    # A valid update rotates the ETag, so stale_etag is now out of date but still a
    # well-formed, once-real token.
    current_etag = cf.update_connection_function(
        Id=fn_id, IfMatch=stale_etag, ConnectionFunctionConfig=_CONFIG, ConnectionFunctionCode=_CODE_V2
    )["ETag"]
    assert current_etag != stale_etag, f"UpdateConnectionFunction did not mint a new ETag ({current_etag!r})"

    # Break exactly one thing: publish with the now-superseded ETag.
    code, message = _error(lambda: cf.publish_connection_function(Id=fn_id, IfMatch=stale_etag))
    assert code == "PreconditionFailed", f"expected PreconditionFailed for a stale ETag, got {code!r}"
    expected_precondition = "Your request is missing requirements for this operation. Update your request and try again."
    assert message == expected_precondition, f"expected message {expected_precondition!r}, got {message!r}"

    # A well-typed string that was never an ETag at all is a distinct, non-version error.
    code, message = _error(lambda: cf.publish_connection_function(Id=fn_id, IfMatch="not-a-real-etag"))
    assert code == "InvalidIfMatchVersion", f"expected InvalidIfMatchVersion for a malformed If-Match, got {code!r}"
    expected_invalid = "The If-Match version is missing or not valid for the resource."
    assert message == expected_invalid, f"expected message {expected_invalid!r}, got {message!r}"

    # Effect absent: an independent read shows the function is still only in DEVELOPMENT.
    still_development = cf.describe_connection_function(Identifier=fn_id)
    assert still_development["ConnectionFunctionSummary"]["Stage"] == "DEVELOPMENT", (
        "a refused publish must not promote the function to LIVE"
    )
    assert still_development["ETag"] == current_etag, "a refused publish must not rotate the ETag"

    # Restore: the identical publish succeeds once given the CURRENT ETag, and promotes to LIVE.
    published = cf.publish_connection_function(Id=fn_id, IfMatch=current_etag)
    assert published["ConnectionFunctionSummary"]["Stage"] == "LIVE"
    live = cf.describe_connection_function(Identifier=fn_id, Stage="LIVE")
    assert live["ConnectionFunctionSummary"]["Stage"] == "LIVE", (
        "an independent read of the LIVE stage after a successful publish must observe LIVE"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
