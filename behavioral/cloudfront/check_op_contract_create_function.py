"""op-contract-createFunction."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-createFunction"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_FUNCTION_CODE = b"""
function handler(event) {
    var request = event.request;
    return request;
}
""".strip()


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateFunction returns a DEVELOPMENT-stage function with ETag; duplicate Name is rejected."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-fn-")

    resp = cf.create_function(
        Name=name,
        FunctionConfig={"Comment": "sim2real behavioral check", "Runtime": "cloudfront-js-2.0"},
        FunctionCode=_FUNCTION_CODE,
    )
    ctx.on_cleanup(lambda: _delete_function(ctx, name))

    summary = resp["FunctionSummary"]
    function_arn = summary["FunctionMetadata"]["FunctionARN"]
    cf.tag_resource(Resource=function_arn, Tags={"Items": [{"Key": "sim2real", "Value": "1"}]})

    assert summary["Name"] == name, f"expected Name {name!r}, got {summary['Name']!r}"
    assert summary["Status"] == "UNPUBLISHED", summary["Status"]
    assert summary["FunctionMetadata"]["Stage"] == "DEVELOPMENT", summary["FunctionMetadata"]["Stage"]
    assert resp.get("ETag"), "expected an ETag on create"
    assert resp.get("Location"), "expected a Location header value"

    # Confirm the function is actually retrievable in DEVELOPMENT stage with matching code.
    # GetFunction returns FunctionCode as a streamed blob, not raw bytes -- it must be read().
    got = cf.get_function(Name=name, Stage="DEVELOPMENT")
    got_code = got["FunctionCode"]
    if hasattr(got_code, "read"):
        got_code = got_code.read()
    assert got_code == _FUNCTION_CODE, f"expected {_FUNCTION_CODE!r}, got {got_code!r}"

    # Distinct error boundary: creating with a Name already in use.
    code, message = _error(
        lambda: cf.create_function(
            Name=name,
            FunctionConfig={"Comment": "dup", "Runtime": "cloudfront-js-2.0"},
            FunctionCode=_FUNCTION_CODE,
        )
    )
    assert code == "FunctionAlreadyExists", f"expected FunctionAlreadyExists, got {code}"
    # AWS answers this refusal with an empty Message element.
    expected = ""
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _delete_function(ctx, name: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        etag = cf.describe_function(Name=name, Stage="DEVELOPMENT")["ETag"]
        cf.delete_function(Name=name, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchFunctionExists":
            raise


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected SUCCESS raises."""
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
