"""cf-function-viewer-request-rewrites-uri-and-headers."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "cf-function-viewer-request-rewrites-uri-and-headers"
GROUP = 'functions'
SERVICES = ['cloudfront']

# Four viewer-request manipulations in one handler, so one TestFunction invocation can be asked
# which of them the edge runtime actually performed:
#   1. rewrite request.uri when it ends in '/'
#   2. copy the querystring value v into a NEW header x-fidelity-v
#   3. delete the incoming header x-drop-me
#   4. leave x-keep-me alone
_FUNCTION_CODE = b"""
function handler(event) {
    var request = event.request;
    if (request.uri.slice(-1) === '/') {
        request.uri = '/rewritten';
    }
    var v = request.querystring['v'];
    if (v) {
        request.headers['x-fidelity-v'] = {value: v.value};
    }
    delete request.headers['x-drop-me'];
    return request;
}
"""

_EVENT = json.dumps({
    "version": "1.0",
    "context": {"eventType": "viewer-request"},
    "viewer": {"ip": "203.0.113.7"},
    "request": {
        "method": "GET",
        "uri": "/a/",
        "querystring": {"v": {"value": "7"}},
        "headers": {"x-drop-me": {"value": "should-not-survive"},
                    "x-keep-me": {"value": "kept"}},
        "cookies": {},
    },
}).encode()


def _force_delete_function(cf, name: str) -> None:
    """ETag-guarded DeleteFunction: CloudFront refuses a delete without the current ETag."""
    cf.delete_function(Name=name, IfMatch=cf.describe_function(Name=name)["ETag"])


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """TestFunction at the DEVELOPMENT stage runs the viewer-request code on the given event with
    no error: the URI becomes /rewritten, the querystring value reaches a new header, one header is
    removed and another kept, and the querystring itself is unchanged."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-behav-fn-rewrite-")

    created = cf.create_function(
        Name=name,
        FunctionConfig={"Comment": "sim2real viewer-request rewrite", "Runtime": "cloudfront-js-2.0"},
        FunctionCode=_FUNCTION_CODE,
    )
    ctx.on_cleanup(lambda: _force_delete_function(cf, name))
    dev_etag = created["ETag"]

    test_result = cf.test_function(Name=name, IfMatch=dev_etag, EventObject=_EVENT)["TestResult"]

    # Real CloudFront reports "no error" as an EMPTY STRING, not an absent field, so assert on
    # falsiness of the value rather than on the key's presence. Checked BEFORE parsing the output:
    # a syntax error in the handler leaves FunctionOutput unusable and the JSON decode would mask
    # the far more readable error message.
    err = test_result.get("FunctionErrorMessage")
    assert not err, (
        f"the edge function errored: {err!r} (logs: {test_result.get('FunctionExecutionLogs')!r})"
    )

    out = json.loads(test_result["FunctionOutput"])
    req = out["request"]
    headers = req["headers"]

    assert req["uri"] == "/rewritten", (
        f"URI was not rewritten by the edge function: {req['uri']!r} (sent '/a/')"
    )
    assert headers["x-fidelity-v"]["value"] == "7", (
        f"the querystring value never reached the new header: {headers.get('x-fidelity-v')!r}"
    )
    assert "x-drop-me" not in headers, (
        f"a header the function deleted survived: {sorted(headers)!r}"
    )
    assert headers["x-keep-me"]["value"] == "kept", (
        f"an untouched header was altered: {headers.get('x-keep-me')!r}"
    )
    # The querystring must be preserved as-is: the handler read it but never wrote it.
    assert req["querystring"]["v"]["value"] == "7", (
        f"the querystring was mutated: {req['querystring']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
