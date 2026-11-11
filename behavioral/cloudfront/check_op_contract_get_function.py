"""op-contract-get-function."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-get-function"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetFunction returns the JS code + content-type for a DEVELOPMENT function, 404s on an
    unknown name, and 404s on that same name once the function is deleted."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-fn-")
    code = b"function handler(event) { return event.request; }"

    create_resp = cf.create_function(
        Name=name,
        FunctionConfig={"Comment": "sim2real behavioral check function", "Runtime": "cloudfront-js-2.0"},
        FunctionCode=code,
    )
    assert create_resp["FunctionSummary"]["FunctionMetadata"]["Stage"] == "DEVELOPMENT"

    def _cleanup(name=name):
        try:
            fresh = cf.describe_function(Name=name)
            cf.delete_function(Name=name, IfMatch=fresh["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchFunctionExists":
                raise

    ctx.on_cleanup(_cleanup)

    # success path
    got = cf.get_function(Name=name)
    # Real CloudFront's exact media type for JS function code varies across API/runtime
    # versions and has been observed to be "application/octet-stream" as well as
    # "application/javascript"-style values, so accept either family rather than
    # asserting an exact string.
    content_type = got["ContentType"].lower()
    assert "javascript" in content_type or content_type == "application/octet-stream", got["ContentType"]
    assert got["FunctionCode"].read() == code
    assert got["ETag"], "GetFunction must return an ETag"

    # error boundary: unknown function name
    err, message = _error(lambda: cf.get_function(Name=ctx.unique_name("sim2real-fn-missing-")))
    assert err == "NoSuchFunctionExists", f"expected NoSuchFunctionExists, got {err}"
    assert message == "The specified function does not exist.", (
        f"expected AWS's exact message, got {message!r}"
    )

    # deletes prove gone: once removed, the exact same GetFunction call 404s, and a
    # second delete against the now-dead name also 404s rather than re-succeeding
    cf.delete_function(Name=name, IfMatch=got["ETag"])
    gone_code, gone_message = _error(lambda: cf.get_function(Name=name))
    assert gone_code == "NoSuchFunctionExists", f"expected NoSuchFunctionExists after delete, got {gone_code}"
    assert gone_message == "The specified function does not exist.", (
        f"expected AWS's exact message, got {gone_message!r}"
    )
    redelete_code, redelete_message = _error(lambda: cf.delete_function(Name=name, IfMatch=got["ETag"]))
    assert redelete_code == "NoSuchFunctionExists", f"expected NoSuchFunctionExists on re-delete, got {redelete_code}"
    assert redelete_message == "The specified function does not exist.", (
        f"expected AWS's exact message, got {redelete_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
