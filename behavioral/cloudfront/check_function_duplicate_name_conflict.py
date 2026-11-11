"""function-duplicate-name-conflict."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a name it should reject is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected FunctionAlreadyExists, but the call SUCCEEDED and returned {result!r}")

def _read_code(cf, name, stage):
    got = cf.get_function(Name=name, Stage=stage)["FunctionCode"]
    return got.read() if hasattr(got, "read") else got

def _force_delete_function(cf, name):
    resp = cf.describe_function(Name=name)
    cf.delete_function(Name=name, IfMatch=resp["ETag"])

CHECK = "function-duplicate-name-conflict"
GROUP = 'overly-permissive'
SERVICES = ['cloudfront']

_FUNCTION_CODE_V1 = b"""
function handler(event) {
    var request = event.request;
    request.headers['x-fidelity-marker'] = {value: 'v1'};
    return request;
}
"""

_FUNCTION_CODE_V2 = b"""
function handler(event) {
    var request = event.request;
    request.headers['x-fidelity-marker'] = {value: 'v2'};
    return request;
}
"""

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: creating a function with an already-used name is rejected, the
    existing function is left byte-for-byte unchanged, and freeing the name (by deleting the
    original) lets the identical second call succeed."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-behav-fn-dup-")

    # Positive control: the name is free, so the first create succeeds.
    created = cf.create_function(
        Name=name,
        FunctionConfig={"Comment": "first", "Runtime": "cloudfront-js-2.0"},
        FunctionCode=_FUNCTION_CODE_V1,
    )
    original_etag = created["ETag"]
    assert created["FunctionSummary"]["FunctionMetadata"]["Stage"] == "DEVELOPMENT", (
        created["FunctionSummary"]["FunctionMetadata"]
    )
    ctx.on_cleanup(lambda: _force_delete_function(cf, name))

    # Break: try to reuse the name while the first function still holds it.
    error = _client_error(lambda: cf.create_function(
        Name=name,
        FunctionConfig={"Comment": "second", "Runtime": "cloudfront-js-2.0"},
        FunctionCode=_FUNCTION_CODE_V2,
    ))
    assert error.get("Code") == "FunctionAlreadyExists", f"expected FunctionAlreadyExists, got {error.get('Code')!r}"
    # AWS sends this refusal with an empty Message element.
    assert error.get("Message") == "", f"expected an empty message, got {error.get('Message')!r}"

    # Effect absent: an independent read shows the name still holds exactly the original
    # function -- the rejected call wrote nothing.
    unchanged = cf.describe_function(Name=name)
    assert unchanged["ETag"] == original_etag, "a rejected CreateFunction still changed the existing function's ETag"
    assert unchanged["FunctionSummary"]["FunctionConfig"]["Comment"] == "first", (
        f"a rejected CreateFunction still overwrote the config: {unchanged['FunctionSummary']['FunctionConfig']!r}"
    )
    assert _read_code(cf, name, "DEVELOPMENT") == _FUNCTION_CODE_V1, (
        "a rejected CreateFunction still overwrote the function code"
    )

    # Restore: free the name by deleting the original, then the identical second call succeeds.
    cf.delete_function(Name=name, IfMatch=original_etag)
    recreated = cf.create_function(
        Name=name,
        FunctionConfig={"Comment": "second", "Runtime": "cloudfront-js-2.0"},
        FunctionCode=_FUNCTION_CODE_V2,
    )
    assert recreated["FunctionSummary"]["FunctionMetadata"]["Stage"] == "DEVELOPMENT", (
        recreated["FunctionSummary"]["FunctionMetadata"]
    )

    # Terminal read: independent of the create response, at the destination.
    assert _read_code(cf, name, "DEVELOPMENT") == _FUNCTION_CODE_V2, (
        "freeing the name did not let the identical call succeed with the second function's code"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
