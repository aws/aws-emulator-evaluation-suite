"""connection-function-deny-and-error-distinguish-test-outputs."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "connection-function-deny-and-error-distinguish-test-outputs"
GROUP = "state-machine"
SERVICES = ["cloudfront"]

_CODE_ALLOW = b"""function connectionHandler(connection) {
    connection.allow();
}
"""
_CODE_DENY = b"""function connectionHandler(connection) {
    connection.deny();
}
"""
_CODE_ERROR = b"""function connectionHandler(connection) {
    throw new Error("sim2real-behav-connfn-deliberate-error");
}
"""


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TestConnectionFunction reports distinct outputs for connection.allow(), connection.deny()
    and an uncaught exception, instead of collapsing every outcome into the same test result."""
    cf = ctx.client("cloudfront")

    if not hasattr(cf, "create_connection_function"):
        raise AssertionError("installed botocore does not support CreateConnectionFunction")

    allow_id, allow_etag = _create(ctx, cf, "allow", _CODE_ALLOW)
    deny_id, deny_etag = _create(ctx, cf, "deny", _CODE_DENY)
    error_id, error_etag = _create(ctx, cf, "error", _CODE_ERROR)

    connection_object = b'{"clientIp":"192.0.2.1","endpoint":"example.cloudfront.net","connectionId":"sim2real-behav-test-connection"}'

    allow_result = cf.test_connection_function(
        Id=allow_id, IfMatch=allow_etag, ConnectionObject=connection_object, Stage="DEVELOPMENT"
    )["ConnectionFunctionTestResult"]
    deny_result = cf.test_connection_function(
        Id=deny_id, IfMatch=deny_etag, ConnectionObject=connection_object, Stage="DEVELOPMENT"
    )["ConnectionFunctionTestResult"]
    error_result = cf.test_connection_function(
        Id=error_id, IfMatch=error_etag, ConnectionObject=connection_object, Stage="DEVELOPMENT"
    )["ConnectionFunctionTestResult"]

    assert not allow_result.get("ConnectionFunctionErrorMessage"), (
        f"connection.allow() must not report an error, got "
        f"{allow_result.get('ConnectionFunctionErrorMessage')!r}"
    )
    assert not deny_result.get("ConnectionFunctionErrorMessage"), (
        f"connection.deny() must not report an error, got "
        f"{deny_result.get('ConnectionFunctionErrorMessage')!r}"
    )
    allow_output = allow_result.get("ConnectionFunctionOutput")
    deny_output = deny_result.get("ConnectionFunctionOutput")
    assert allow_output, f"expected a non-empty ConnectionFunctionOutput for connection.allow(), got {allow_output!r}"
    assert deny_output, f"expected a non-empty ConnectionFunctionOutput for connection.deny(), got {deny_output!r}"
    assert allow_output != deny_output, (
        f"connection.allow() and connection.deny() must produce distinct ConnectionFunctionOutput, "
        f"both were {allow_output!r}"
    )

    error_message = error_result.get("ConnectionFunctionErrorMessage")
    assert error_message, (
        f"an uncaught exception must report a non-empty ConnectionFunctionErrorMessage, got {error_message!r}"
    )
    assert "sim2real-behav-connfn-deliberate-error" in error_message, (
        f"expected the deliberate error text in ConnectionFunctionErrorMessage, got {error_message!r}"
    )


def _create(ctx, cf, label: str, code: bytes) -> tuple[str, str]:
    name = ctx.unique_name(f"sim2real-connfn-{label}-")
    created = cf.create_connection_function(
        Name=name,
        ConnectionFunctionConfig={"Comment": f"sim2real-behav {label}", "Runtime": "cloudfront-js-2.0"},
        ConnectionFunctionCode=code,
    )
    fn_id = created["ConnectionFunctionSummary"]["Id"]
    etag = created["ETag"]

    def _cleanup() -> None:
        try:
            current_etag = cf.get_connection_function(Identifier=fn_id)["ETag"]
        except cf.exceptions.EntityNotFound:
            return
        cf.delete_connection_function(Id=fn_id, IfMatch=current_etag)

    ctx.on_cleanup(_cleanup)
    return fn_id, etag


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
