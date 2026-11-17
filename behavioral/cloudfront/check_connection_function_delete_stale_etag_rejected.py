"""connection-function-delete-stale-etag-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "connection-function-delete-stale-etag-rejected"
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
    """DeleteConnectionFunction with an ETag a later update superseded fails with PreconditionFailed
    and its exact message, leaving the function in place; the identical delete then succeeds once it
    presents the current ETag.
    """
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-connfn-delstale-")[:64]

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

    # Break exactly one thing: delete with the now-superseded ETag.
    code, message = _error(lambda: cf.delete_connection_function(Id=fn_id, IfMatch=stale_etag))
    assert code == "PreconditionFailed", f"expected PreconditionFailed for a stale ETag, got {code!r}"
    expected = "Your request is missing requirements for this operation. Update your request and try again."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: an independent read shows the function is still there, unchanged.
    still_there = cf.describe_connection_function(Identifier=fn_id)
    assert still_there["ConnectionFunctionSummary"]["Id"] == fn_id, "a refused delete must leave the function in place"
    assert still_there["ETag"] == current_etag, "a refused delete must not rotate the ETag"

    # Restore: the identical delete succeeds once given the CURRENT ETag.
    cf.delete_connection_function(Id=fn_id, IfMatch=current_etag)
    gone_code, gone_message = _error(lambda: cf.describe_connection_function(Identifier=fn_id))
    assert gone_code == "EntityNotFound", f"expected EntityNotFound after delete, got {gone_code!r}"
    assert gone_message == "The specified connection function does not exist.", (
        f"expected the exact not-found message, got {gone_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
