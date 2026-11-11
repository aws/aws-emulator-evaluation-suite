"""function-update-requires-current-etag."""
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

def _force_delete_function(cf, name):
    resp = cf.describe_function(Name=name)
    cf.delete_function(Name=name, IfMatch=resp["ETag"])

CHECK = "function-update-requires-current-etag"
GROUP = 'functions'
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
    """UpdateFunction rejects a stale ETag and applies changes when given the current one."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-behav-fn-update-")
    created = cf.create_function(
        Name=name,
        FunctionConfig={"Comment": "v1", "Runtime": "cloudfront-js-2.0"},
        FunctionCode=_FUNCTION_CODE_V1,
        Tags={"Items": [{"Key": "sim2real", "Value": "true"}]},
    )
    ctx.on_cleanup(lambda: _force_delete_function(cf, name))
    stale_etag = created["ETag"]

    updated = cf.update_function(
        Name=name, IfMatch=stale_etag,
        FunctionConfig={"Comment": "v2", "Runtime": "cloudfront-js-2.0"},
        FunctionCode=_FUNCTION_CODE_V2,
    )
    comment = updated["FunctionSummary"]["FunctionConfig"]["Comment"]
    assert comment == "v2", f"expected the current-ETag update to apply, got Comment={comment!r}"

    code, message = _error(lambda: cf.update_function(
        Name=name, IfMatch=stale_etag,
        FunctionConfig={"Comment": "v3", "Runtime": "cloudfront-js-2.0"},
        FunctionCode=_FUNCTION_CODE_V1,
    ))
    assert code == "PreconditionFailed", f"expected PreconditionFailed for stale function ETag, got {code}"
    stale_message = (
        "The request failed because it didn't meet the preconditions in one or more request-header fields."
    )
    assert message == stale_message, f"expected message {stale_message!r}, got {message!r}"

    # Independent read at the destination: the rejected update must not have applied.
    still = cf.describe_function(Name=name)
    still_comment = still["FunctionSummary"]["FunctionConfig"]["Comment"]
    assert still_comment == "v2", f"expected rejected update to leave Comment='v2', got {still_comment!r}"

    # Restore: the identical update, retried with the current ETag, now succeeds.
    current_etag = still["ETag"]
    cf.update_function(
        Name=name, IfMatch=current_etag,
        FunctionConfig={"Comment": "v3", "Runtime": "cloudfront-js-2.0"},
        FunctionCode=_FUNCTION_CODE_V1,
    )
    restored = cf.describe_function(Name=name)
    restored_comment = restored["FunctionSummary"]["FunctionConfig"]["Comment"]
    assert restored_comment == "v3", f"expected the retried update with the current ETag to apply, got Comment={restored_comment!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
