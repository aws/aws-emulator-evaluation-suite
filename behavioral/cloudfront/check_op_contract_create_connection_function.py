"""op-contract-create-connection-function."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-create-connection-function"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConnectionFunction creates a function in DEVELOPMENT that DescribeConnectionFunction reads
    back, and a second create with the same Name is refused with EntityAlreadyExists and the exact
    message and leaves the original's ETag unchanged."""

    cf = ctx.client("cloudfront")
    if not hasattr(cf, "create_connection_function"):
        raise AssertionError("create_connection_function not in installed botocore")

    name = ctx.unique_name("sim2real-behav-connfn-").replace("-", "")[:64]
    code_body = b"function handler(event) { return event.request; }"
    config = {"Comment": "sim2real behavioral check", "Runtime": "cloudfront-js-2.0"}
    tag_set = {"Items": [{"Key": "sim2real", "Value": CHECK}]}

    try:
        resp = cf.create_connection_function(
            Name=name, ConnectionFunctionConfig=config, ConnectionFunctionCode=code_body, Tags=tag_set
        )
    except Exception as exc:
        err_code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if err_code == "UnsupportedOperation":
            raise AssertionError("connection functions not enabled on this account")
        raise

    summary = resp["ConnectionFunctionSummary"]
    fn_id = summary["Id"]
    etag = resp["ETag"]
    ctx.on_cleanup(lambda: cf.delete_connection_function(Id=fn_id, IfMatch=etag))

    assert summary["Name"] == name
    assert summary["Stage"] == "DEVELOPMENT", summary["Stage"]

    # Independent read at the destination: the create response is never the verdict.
    described = cf.describe_connection_function(Identifier=fn_id)["ConnectionFunctionSummary"]
    assert described["Name"] == name, (
        f"independent DescribeConnectionFunction read: expected Name {name!r}, got {described['Name']!r}"
    )
    assert described["Stage"] == "DEVELOPMENT", described["Stage"]

    # Error boundary: duplicate Name is rejected.
    err_code, err_message = _error(
        lambda: cf.create_connection_function(
            Name=name, ConnectionFunctionConfig=config, ConnectionFunctionCode=code_body
        )
    )
    assert err_code == "EntityAlreadyExists", f"expected EntityAlreadyExists, got {err_code}"
    expected = "A connection function with the same name already exists in this AWS account."
    assert err_message == expected, f"expected message {expected!r}, got {err_message!r}"

    # Effect absent: the rejected duplicate must not have touched the original, proven by
    # an independent read (not the mutating create call itself).
    unaffected = cf.describe_connection_function(Identifier=fn_id)
    assert unaffected["ETag"] == etag, (
        f"a rejected duplicate CreateConnectionFunction must not modify the original: "
        f"expected ETag {etag!r} via independent read, got {unaffected['ETag']!r}"
    )


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected success raises,
    so a target that accepts what AWS refuses fails as an accepted call, not as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
