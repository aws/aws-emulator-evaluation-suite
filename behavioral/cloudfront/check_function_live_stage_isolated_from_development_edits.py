"""function-live-stage-isolated-from-development-edits."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _force_delete_function(cf, name):
    try:
        resp = cf.describe_function(Name=name)
        cf.delete_function(Name=name, IfMatch=resp["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchFunctionExists":
            raise

CHECK = "function-live-stage-isolated-from-development-edits"
GROUP = 'functions'
SERVICES = ['cloudfront']

def _function_code_bytes(resp: dict) -> bytes:
    """Normalize GetFunction's FunctionCode member to bytes.

    botocore models this blob as a streaming payload, so real AWS hands back a
    StreamingBody rather than bytes; an emulator may return either.
    """
    body = resp["FunctionCode"]
    if hasattr(body, "read"):
        body = body.read()
    return bytes(body)

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

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Editing the DEVELOPMENT stage after a publish must not retroactively change the LIVE stage."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-behav-fn-isolation-")
    created = cf.create_function(
        Name=name,
        FunctionConfig={"Comment": "v1", "Runtime": "cloudfront-js-2.0"},
        FunctionCode=_FUNCTION_CODE_V1,
    )
    ctx.on_cleanup(lambda: _force_delete_function(cf, name))
    dev_etag = created["ETag"]

    cf.publish_function(Name=name, IfMatch=dev_etag)
    live_code_v1 = _function_code_bytes(cf.get_function(Name=name, Stage="LIVE"))
    assert live_code_v1 == _FUNCTION_CODE_V1, (
        f"LIVE stage should serve the published code, got {live_code_v1!r}")

    # edit DEVELOPMENT again without publishing
    dev_desc = cf.describe_function(Name=name, Stage="DEVELOPMENT")
    updated = cf.update_function(
        Name=name, IfMatch=dev_desc["ETag"],
        FunctionConfig={"Comment": "v2-unpublished", "Runtime": "cloudfront-js-2.0"},
        FunctionCode=_FUNCTION_CODE_V2,
    )

    live_code_after_edit = _function_code_bytes(cf.get_function(Name=name, Stage="LIVE"))
    assert live_code_after_edit == _FUNCTION_CODE_V1, "unpublished DEVELOPMENT edits must not affect LIVE stage"

    dev_code_after_edit = _function_code_bytes(cf.get_function(Name=name, Stage="DEVELOPMENT"))
    assert dev_code_after_edit == _FUNCTION_CODE_V2, "DEVELOPMENT stage should reflect the latest edit"

    # teardown is already mandatory; make the delete itself a proved negative
    # instead of an unasserted side effect.
    cf.delete_function(Name=name, IfMatch=updated["ETag"])
    gone_code, gone_message = _error(lambda: cf.describe_function(Name=name))
    assert gone_code == "NoSuchFunctionExists", f"expected NoSuchFunctionExists after delete, got {gone_code}"
    not_found_message = "The specified function does not exist."
    assert gone_message == not_found_message, f"expected message {not_found_message!r}, got {gone_message!r}"


def _error(fn) -> tuple[str, str]:
    """Run a call AWS refuses; return its (code, message). Raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
