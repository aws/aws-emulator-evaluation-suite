"""delete-function-stale-etag-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-function-stale-etag-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_FUNCTION_CODE = b"""
function handler(event) {
    return event.request;
}
""".strip()


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteFunction rejects a stale/incorrect IfMatch value with InvalidIfMatchVersion, and
    the identical call with the current ETag then succeeds (the positive control that separates
    "rejects a stale ETag" from "rejects every DeleteFunction call")."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-fn-etag-")

    cf.create_function(
        Name=name,
        FunctionConfig={"Comment": "sim2real behavioral check", "Runtime": "cloudfront-js-2.0"},
        FunctionCode=_FUNCTION_CODE,
        Tags={"Items": [{"Key": "sim2real", "Value": "behavioral"}]},
    )
    ctx.on_cleanup(lambda: _delete_function(ctx, name))

    real_etag = cf.describe_function(Name=name, Stage="DEVELOPMENT")["ETag"]
    stale_etag = real_etag[:-1] + ("0" if real_etag[-1] != "0" else "1")

    code, message = _error(lambda: cf.delete_function(Name=name, IfMatch=stale_etag))
    assert code == "InvalidIfMatchVersion", f"expected InvalidIfMatchVersion, got {code}"
    assert message == "The If-Match version is missing or not valid for the resource.", f"unexpected InvalidIfMatchVersion message: {message!r}"

    # Function must still exist after the rejected delete.
    still_there = cf.describe_function(Name=name, Stage="DEVELOPMENT")
    assert still_there["FunctionSummary"]["Name"] == name

    # Restore: the identical call with the CURRENT ETag now succeeds, proving the stale-etag
    # rejection above was about the ETag and not a blanket refusal of DeleteFunction.
    cf.delete_function(Name=name, IfMatch=real_etag)

    gone_code, gone_message = _error(lambda: cf.describe_function(Name=name, Stage="DEVELOPMENT"))
    assert gone_code == "NoSuchFunctionExists", f"expected NoSuchFunctionExists, got {gone_code}"
    assert gone_message == "The specified function does not exist.", f"unexpected NoSuchFunctionExists message: {gone_message!r}"

    # A mutation on the now-dead id also fails, specifically.
    dead_code, dead_message = _error(lambda: cf.delete_function(Name=name, IfMatch=real_etag))
    assert dead_code == "NoSuchFunctionExists", f"expected NoSuchFunctionExists, got {dead_code}"
    assert dead_message == "The specified function does not exist.", f"unexpected NoSuchFunctionExists message: {dead_message!r}"


def _delete_function(ctx, name: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        etag = cf.describe_function(Name=name, Stage="DEVELOPMENT")["ETag"]
        cf.delete_function(Name=name, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchFunctionExists":
            raise


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
