"""function-delete-stale-etag-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn) -> tuple[str, str]:
    """Run a call AWS refuses; return its (code, message). Raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")

def _cleanup_function(cf, name):
    try:
        fresh = cf.describe_function(Name=name, Stage="DEVELOPMENT")
        cf.delete_function(Name=name, IfMatch=fresh["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchFunctionExists":
            raise

CHECK = "function-delete-stale-etag-fails"
GROUP = 'overly-permissive'
SERVICES = ['cloudfront']

_FUNCTION_CODE = b"""
function handler(event) {
    var request = event.request;
    request.headers['x-test-header'] = { value: 'test-value' };
    return request;
}
""".strip()

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteFunction with a stale/incorrect IfMatch MUST fail with InvalidIfMatchVersion, leaving
    the function untouched; the identical delete with the current ETag then succeeds, and the
    deleted function is gone and unusable."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-behav-fn-stale-")
    create_resp = cf.create_function(
        Name=name,
        FunctionConfig={"Comment": "behavioral test", "Runtime": "cloudfront-js-2.0"},
        FunctionCode=_FUNCTION_CODE,
    )
    ctx.on_cleanup(lambda: _cleanup_function(cf, name))
    real_etag = create_resp["ETag"]
    bogus_etag = real_etag[::-1] if real_etag[::-1] != real_etag else real_etag + "x"

    code, message = _error(lambda: cf.delete_function(Name=name, IfMatch=bogus_etag))
    assert code == "InvalidIfMatchVersion", f"expected InvalidIfMatchVersion, got {code}"
    stale_message = "The If-Match version is missing or not valid for the resource."
    assert message == stale_message, f"expected message {stale_message!r}, got {message!r}"

    # The function must still exist, with its ETag unchanged, since the delete was rejected.
    still = cf.describe_function(Name=name, Stage="DEVELOPMENT")
    got_name = still["FunctionSummary"]["Name"]
    assert got_name == name, f"expected function {name} to still exist, got {got_name}"
    current_etag = still["ETag"]
    assert current_etag == real_etag, (
        f"ETag must be unchanged by a rejected delete, expected {real_etag}, got {current_etag}"
    )

    # Restore: the identical call with the correct, current ETag now succeeds.
    cf.delete_function(Name=name, IfMatch=current_etag)

    # Independent read proves the function is gone.
    not_found_message = "The specified function does not exist."
    gone_code, gone_message = _error(lambda: cf.describe_function(Name=name, Stage="DEVELOPMENT"))
    assert gone_code == "NoSuchFunctionExists", f"expected NoSuchFunctionExists, got {gone_code}"
    assert gone_message == not_found_message, f"expected message {not_found_message!r}, got {gone_message!r}"

    # A further mutation on the now-dead id fails the same way, not by coincidence.
    double_delete_code, double_delete_message = _error(lambda: cf.delete_function(Name=name, IfMatch=current_etag))
    assert double_delete_code == "NoSuchFunctionExists", (
        f"expected NoSuchFunctionExists on double-delete, got {double_delete_code}"
    )
    assert double_delete_message == not_found_message, (
        f"expected message {not_found_message!r}, got {double_delete_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
