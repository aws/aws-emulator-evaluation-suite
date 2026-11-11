"""function-development-to-live-publish-lifecycle."""
from __future__ import annotations

import json

from behavioral_harness import tags

def _force_delete_function(cf, name):
    resp = cf.describe_function(Name=name)
    cf.delete_function(Name=name, IfMatch=resp["ETag"])

CHECK = "function-development-to-live-publish-lifecycle"
GROUP = 'functions'
SERVICES = ['cloudfront']

_FUNCTION_CODE_V1 = b"""
function handler(event) {
    var request = event.request;
    request.headers['x-fidelity-marker'] = {value: 'v1'};
    return request;
}
"""

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A function starts in DEVELOPMENT, runs via TestFunction, then PublishFunction promotes it to LIVE."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-behav-fn-lifecycle-")
    created = cf.create_function(
        Name=name,
        FunctionConfig={"Comment": "fidelity", "Runtime": "cloudfront-js-2.0"},
        FunctionCode=_FUNCTION_CODE_V1,
    )
    ctx.on_cleanup(lambda: _force_delete_function(cf, name))
    created_stage = created["FunctionSummary"]["FunctionMetadata"]["Stage"]
    assert created_stage == "DEVELOPMENT", f"a freshly created function must start in DEVELOPMENT, got {created_stage!r}"
    dev_etag = created["ETag"]

    test_event = (
        b'{"version":"1.0","context":{"eventType":"viewer-request"},'
        b'"viewer":{"ip":"1.2.3.4"},'
        b'"request":{"method":"GET","uri":"/","headers":{},"cookies":{},"querystring":{}}}'
    )
    test_result = cf.test_function(Name=name, IfMatch=dev_etag, EventObject=test_event)["TestResult"]
    # Real CloudFront reports "no error" as an EMPTY STRING, not an absent/None field.
    err = test_result.get("FunctionErrorMessage")
    assert not err, f"unexpected function error: {err!r} (full result: {test_result})"
    # The function actually executed: its mutation must be visible in the output, with the
    # exact value the handler wrote — not merely present somewhere in the raw output blob.
    output_headers = json.loads(test_result["FunctionOutput"])["request"]["headers"]
    assert output_headers.get("x-fidelity-marker", {}).get("value") == "v1", (
        f"TestFunction must return the mutated request with x-fidelity-marker=v1, got {output_headers}")
    assert test_result["FunctionSummary"]["FunctionMetadata"]["Stage"] == "DEVELOPMENT", (
        "TestFunction against the DEVELOPMENT ETag must report the DEVELOPMENT stage")

    published = cf.publish_function(Name=name, IfMatch=dev_etag)
    assert published["FunctionSummary"]["FunctionMetadata"]["Stage"] == "LIVE", "publish must promote to LIVE stage"

    live_desc = cf.describe_function(Name=name, Stage="LIVE")
    live_stage = live_desc["FunctionSummary"]["FunctionMetadata"]["Stage"]
    assert live_stage == "LIVE", f"describe_function(Stage='LIVE') after publish must report LIVE, got {live_stage!r}"
    # Real CloudFront does NOT rotate the ETag on publish — DescribeFunction returns the SAME
    # ETag for the DEVELOPMENT and LIVE stages of the same function. Assert that identity
    # directly rather than merely that the LIVE stage has *some* ETag.
    assert live_desc.get("ETag") == dev_etag, (
        f"publish must not rotate the ETag: DEVELOPMENT was {dev_etag!r}, LIVE is {live_desc.get('ETag')!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
