"""op-contract-describeFunction."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-describeFunction"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeFunction: reflects the DEVELOPMENT stage of a freshly created
    CloudFront Function, and rejects a Stage lookup for a stage the function
    has never reached (NoSuchFunctionExists for Stage=LIVE before publish)."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-cffn-").replace("-", "_")
    code_body = b"function handler(event) { return event.request; }"

    created = cf.create_function(
        Name=name,
        FunctionConfig={"Comment": "sim2real behavioral check", "Runtime": "cloudfront-js-2.0"},
        FunctionCode=code_body,
    )
    etag = created["ETag"]
    stage = created["FunctionSummary"]["FunctionMetadata"]["Stage"]
    assert stage == "DEVELOPMENT", f"expected DEVELOPMENT on create, got {stage}"
    ctx.on_cleanup(lambda: _safe_delete(cf, name))

    described = cf.describe_function(Name=name)
    summary = described["FunctionSummary"]
    assert summary["Name"] == name, f"expected Name {name!r}, got {summary['Name']!r}"
    assert summary["FunctionMetadata"]["Stage"] == "DEVELOPMENT", (
        f"expected DEVELOPMENT, got {summary['FunctionMetadata']['Stage']}"
    )
    assert described["ETag"] == etag, f"expected ETag {etag!r}, got {described['ETag']!r}"

    # distinct error boundary: the function has never been published to LIVE
    code, msg = _error(lambda: cf.describe_function(Name=name, Stage="LIVE"))
    assert code == "NoSuchFunctionExists", f"expected NoSuchFunctionExists, got {code}"
    assert msg == "The specified function does not exist.", f"unexpected NoSuchFunctionExists message: {msg!r}"

    # restore leg: LIVE is a reachable stage, not a permanently invalid input --
    # publish and demand the identical Stage=LIVE lookup that was just rejected
    # now succeeds. Without this, a target that rejects every Stage=LIVE lookup
    # regardless of publish state would pass the rejection above unchallenged.
    published = cf.publish_function(Name=name, IfMatch=etag)
    published_stage = published["FunctionSummary"]["FunctionMetadata"]["Stage"]
    assert published_stage == "LIVE", f"expected LIVE after publish, got {published_stage}"

    live = cf.describe_function(Name=name, Stage="LIVE")
    live_stage = live["FunctionSummary"]["FunctionMetadata"]["Stage"]
    assert live_stage == "LIVE", f"expected LIVE for a published function, got {live_stage}"
    assert live.get("ETag"), "expected DescribeFunction(Stage=LIVE) to return an ETag"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    succeeds raises AssertionError: an emulator accepting input real AWS refuses must fail
    loudly, not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _safe_delete(cf, name: str) -> None:
    try:
        current = cf.describe_function(Name=name)
        cf.delete_function(Name=name, IfMatch=current["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchFunctionExists":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
