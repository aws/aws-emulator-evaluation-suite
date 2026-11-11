"""overly-permissive-function-publish-stale-etag-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "overly-permissive-function-publish-stale-etag-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PublishFunction with a stale If-Match fails PreconditionFailed and promotes nothing to LIVE;
    with the current ETag it succeeds and LIVE serves the current revision, not the stale one.
    """
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-behav-cf-fnstale-")
    created = cf.create_function(
        Name=name,
        FunctionConfig={"Comment": "v1", "Runtime": "cloudfront-js-2.0"},
        FunctionCode=_function_code(b"v1"),
    )
    ctx.on_cleanup(lambda: _cleanup_function(cf, name))
    stale_etag = created["ETag"]

    updated = cf.update_function(
        Name=name,
        IfMatch=stale_etag,
        FunctionConfig={"Comment": "v2", "Runtime": "cloudfront-js-2.0"},
        FunctionCode=_function_code(b"v2"),
    )
    current_etag = updated["ETag"]

    # The break: publish with the now-stale (pre-update) ETag must be refused.
    code, message = _error(lambda: cf.publish_function(Name=name, IfMatch=stale_etag))
    assert code == "PreconditionFailed", (
        f"PublishFunction with a stale IfMatch must fail with PreconditionFailed, got {code!r}")
    expected = "The request failed because it didn't meet the preconditions in one or more request-header fields."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect-absent: the rejected publish must not have promoted anything to LIVE.
    assert name not in _list_stage_names(cf, "LIVE"), (
        f"{name} must not appear under Stage=LIVE after a rejected PublishFunction")

    # Restore: the identical operation with the CURRENT ETag must succeed.
    published = cf.publish_function(Name=name, IfMatch=current_etag)
    live_stage = published["FunctionSummary"]["FunctionMetadata"]["Stage"]
    assert live_stage == "LIVE", f"publish with the current ETag must promote to LIVE, got {live_stage!r}"

    # Independent read at the destination: LIVE serves the v2 code that was actually
    # published, never the v1 code the rejected stale-ETag call tried to promote.
    live_code = _function_code_bytes(cf.get_function(Name=name, Stage="LIVE"))
    assert live_code == _function_code(b"v2"), (
        f"LIVE must serve the v2 code that was actually published, got {live_code!r}")




def _function_code(version: bytes) -> bytes:
    return b"function handler(event) {\n    return event.request;\n} // " + version + b"\n"


def _function_code_bytes(resp: dict) -> bytes:
    """Normalize GetFunction's FunctionCode member to bytes.

    botocore models this blob as a streaming payload, so AWS returns a StreamingBody, not bytes.
    """
    body = resp["FunctionCode"]
    if hasattr(body, "read"):
        body = body.read()
    return bytes(body)


def _list_stage_names(cf, stage: str) -> set[str]:
    names: set[str] = set()
    marker = ""
    while True:
        kwargs = {"Stage": stage}
        if marker:
            kwargs["Marker"] = marker
        resp = cf.list_functions(**kwargs)
        flist = resp.get("FunctionList", {})
        for item in flist.get("Items", []):
            names.add(item["Name"])
        marker = flist.get("NextMarker", "")
        if not marker:
            break
    return names


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises,
    so a call AWS refuses is never read as a mere code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _cleanup_function(cf, name: str) -> None:
    """DeleteFunction needs the CURRENT ETag, so re-read it at teardown time."""
    try:
        cur = cf.describe_function(Name=name)
        cf.delete_function(Name=name, IfMatch=cur["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchFunctionExists":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
