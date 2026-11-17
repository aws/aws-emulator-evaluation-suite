"""connection-function-update-stale-etag-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "connection-function-update-stale-etag-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_CONFIG = {"Comment": "sim2real-behav", "Runtime": "cloudfront-js-2.0"}
_CODE_V1 = b"function connectionHandler(connection) {\n    connection.allow();\n}\n"
_CODE_V2 = b"function connectionHandler(connection) {\n    connection.allow();\n    // v2\n}\n"
_CODE_V3 = b"function connectionHandler(connection) {\n    connection.allow();\n    // v3\n}\n"


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected success raises,
    so a target that accepts what AWS refuses fails as an accepted call, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _code_of(resp):
    body = resp["ConnectionFunctionCode"]
    return body.read() if hasattr(body, "read") else body


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A superseded If-Match on UpdateConnectionFunction fails with PreconditionFailed and leaves
    the code and ETag unchanged; a never-issued If-Match fails with InvalidIfMatchVersion instead;
    the identical update then succeeds once it presents the current ETag.
    """
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-connfn-stale-")[:64]

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

    # Positive control: a valid update with the current ETag succeeds and mints a new one,
    # which makes stale_etag out of date but still a well-formed, once-real token.
    first = cf.update_connection_function(
        Id=fn_id, IfMatch=stale_etag, ConnectionFunctionConfig=_CONFIG, ConnectionFunctionCode=_CODE_V2
    )
    current_etag = first["ETag"]
    assert current_etag != stale_etag, f"UpdateConnectionFunction did not mint a new ETag ({current_etag!r})"

    # Break exactly one thing: present the now-superseded ETag.
    code, message = _error(
        lambda: cf.update_connection_function(
            Id=fn_id, IfMatch=stale_etag, ConnectionFunctionConfig=_CONFIG, ConnectionFunctionCode=_CODE_V3
        )
    )
    assert code == "PreconditionFailed", f"expected PreconditionFailed for a stale ETag, got {code!r}"
    expected_precondition = "Your request is missing requirements for this operation. Update your request and try again."
    assert message == expected_precondition, f"expected message {expected_precondition!r}, got {message!r}"

    # A well-typed string that was never an ETag at all is a distinct, non-version error.
    code, message = _error(
        lambda: cf.update_connection_function(
            Id=fn_id, IfMatch="not-a-real-etag", ConnectionFunctionConfig=_CONFIG, ConnectionFunctionCode=_CODE_V3
        )
    )
    assert code == "InvalidIfMatchVersion", f"expected InvalidIfMatchVersion for a malformed If-Match, got {code!r}"
    expected_invalid = "The If-Match version is missing or not valid for the resource."
    assert message == expected_invalid, f"expected message {expected_invalid!r}, got {message!r}"

    # Effect absent: an independent read still shows v2's code under the same ETag.
    unchanged = cf.get_connection_function(Identifier=fn_id)
    assert _code_of(unchanged) == _CODE_V2, "a refused update must not change the code"
    assert unchanged["ETag"] == current_etag, "a refused update must not rotate the ETag"

    # Restore: the identical update succeeds once given the CURRENT ETag.
    restored = cf.update_connection_function(
        Id=fn_id, IfMatch=current_etag, ConnectionFunctionConfig=_CONFIG, ConnectionFunctionCode=_CODE_V3
    )
    assert restored["ETag"] != current_etag, "the restoring update did not mint a new ETag"
    reread = cf.get_connection_function(Identifier=fn_id)
    assert _code_of(reread) == _CODE_V3, "the restoring update's code did not apply"
    assert reread["ETag"] == restored["ETag"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
