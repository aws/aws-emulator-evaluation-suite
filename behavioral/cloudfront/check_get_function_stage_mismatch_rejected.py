"""get-function-stage-mismatch-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-function-stage-mismatch-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetFunction(Name=<valid DEVELOPMENT-only function>, Stage='LIVE') must be rejected with
    NoSuchFunctionExists: a valid name in the wrong stage is a distinct boundary from an unknown name."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-fnstage-")
    code = b"function handler(event) { return event.request; }"

    cf.create_function(
        Name=name,
        FunctionConfig={"Comment": "sim2real behavioral check function", "Runtime": "cloudfront-js-2.0"},
        FunctionCode=code,
    )
    ctx.on_cleanup(lambda: cf.delete_function(Name=name, IfMatch=cf.describe_function(Name=name)["ETag"]))

    # sanity: the function does exist in DEVELOPMENT stage
    dev = cf.get_function(Name=name, Stage="DEVELOPMENT")
    assert dev["FunctionCode"].read() == code, "sanity: DEVELOPMENT stage must serve the created code"

    # the same name never published to LIVE must be rejected, not silently fall back to DEVELOPMENT
    err, message = _error(lambda: cf.get_function(Name=name, Stage="LIVE"))
    assert err == "NoSuchFunctionExists", f"expected NoSuchFunctionExists for wrong stage, got {err}"
    assert message == "The specified function does not exist.", (
        f"expected AWS's exact message, got {message!r}"
    )

    # restore: publishing the function is what makes the LIVE stage exist, and the
    # identical GetFunction(Stage="LIVE") call that was just rejected must now succeed.
    published = cf.publish_function(Name=name, IfMatch=dev["ETag"])
    assert published["FunctionSummary"]["FunctionMetadata"]["Stage"] == "LIVE", (
        f"publish must promote the function to LIVE, got {published['FunctionSummary']['FunctionMetadata']}")

    live = cf.get_function(Name=name, Stage="LIVE")
    assert live["FunctionCode"].read() == code, (
        "GetFunction(Stage=LIVE) must now succeed and serve the published code")


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
