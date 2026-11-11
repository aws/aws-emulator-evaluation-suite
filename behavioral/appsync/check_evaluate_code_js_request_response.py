"""evaluate-code-js-request-response."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "evaluate-code-js-request-response"
GROUP = "data-plane"
SERVICES = ["appsync"]

_RUNTIME = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}
_CODE = """
export function request(ctx) {
  return { payload: ctx.args };
}

export function response(ctx) {
  return ctx.result.name.toUpperCase();
}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """EvaluateCode actually executes the APPSYNC_JS request()/response() handlers:
    request() maps ctx.args into a payload and response() performs a real JS
    string transform (toUpperCase) on ctx.result -- not a passthrough stub."""
    appsync = ctx.client("appsync")

    req_context = json.dumps(
        {
            "arguments": {"name": "world"},
            "stash": {},
            "result": None,
            "source": None,
            "identity": None,
            "info": {"fieldName": "test", "parentTypeName": "Query", "variables": {}},
            "request": {"headers": {}},
        }
    )
    req_resp = appsync.evaluate_code(
        runtime=_RUNTIME, code=_CODE, context=req_context, function="request"
    )
    assert not req_resp.get("error"), f"unexpected error: {req_resp.get('error')}"
    request_result = json.loads(req_resp["evaluationResult"])
    assert request_result == {"payload": {"name": "world"}}, (
        f"expected request() to map ctx.args into payload, got {request_result!r}"
    )

    resp_context = json.dumps(
        {
            "arguments": {},
            "stash": {},
            "result": {"name": "world"},
            "source": None,
            "identity": None,
            "info": {"fieldName": "test", "parentTypeName": "Query", "variables": {}},
            "request": {"headers": {}},
        }
    )
    resp_resp = appsync.evaluate_code(
        runtime=_RUNTIME, code=_CODE, context=resp_context, function="response"
    )
    assert not resp_resp.get("error"), f"unexpected error: {resp_resp.get('error')}"
    response_result = json.loads(resp_resp["evaluationResult"])
    assert response_result == "WORLD", (
        f"expected response() toUpperCase() transform to yield 'WORLD', got {response_result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
