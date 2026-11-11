"""op-contract-deleteFunction."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteFunction"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_CODE = b"function handler(event) {\n    return event.request;\n}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteFunction: a stale IfMatch is rejected distinctly from a correct delete,
    which removes the CloudFront Function so Describe reports NotFound."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-fn-")[:64]

    created = cf.create_function(
        Name=name,
        FunctionConfig={"Comment": "sim2real behavioral check", "Runtime": "cloudfront-js-2.0"},
        FunctionCode=_CODE,
    )
    etag = created["ETag"]

    def _cleanup(name=name):
        try:
            fresh = cf.describe_function(Name=name)
            cf.delete_function(Name=name, IfMatch=fresh["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchFunctionExists":
                raise

    ctx.on_cleanup(_cleanup)

    # error boundary: garbled IfMatch while the function still exists
    bad_code, bad_message = _error(lambda: cf.delete_function(Name=name, IfMatch='"bogus-etag"'))
    assert bad_code == "InvalidIfMatchVersion", f"expected InvalidIfMatchVersion, got {bad_code}"
    assert bad_message == "The If-Match version is missing or not valid for the resource.", (
        f"expected the exact refusal message, got {bad_message!r}"
    )

    # success path
    cf.delete_function(Name=name, IfMatch=etag)
    gone_code, gone_message = _error(lambda: cf.describe_function(Name=name))
    assert gone_code == "NoSuchFunctionExists", f"expected NoSuchFunctionExists, got {gone_code}"
    assert gone_message == "The specified function does not exist.", (
        f"expected the exact refusal message, got {gone_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises,
    because an emulator accepting input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
