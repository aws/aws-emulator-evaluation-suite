"""evaluate-code-js-runtime-error."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "evaluate-code-js-runtime-error"
GROUP = "data-plane"
SERVICES = ["appsync"]

_RUNTIME = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}
_CODE = """
export function request(ctx) {
  util.error("bad-request-boom");
}

export function response(ctx) {
  return ctx.result;
}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """util.error() in an APPSYNC_JS request() handler surfaces in EvaluateCode's error.message with no
    evaluationResult, while the module's response() handler still echoes ctx.result."""
    appsync = ctx.client("appsync")

    # Positive control: the SAME code module, evaluated via its OTHER export
    # (response(), which has no util.error() call). This proves the module compiles
    # and the evaluator is genuinely healthy on this runtime -- a target that always
    # returns an error for every evaluate_code call, or that rejects the whole module
    # at compile time, fails here first.
    response_context = json.dumps(
        {
            "arguments": {},
            "stash": {},
            "result": {"ok": True, "n": 7},
            "source": None,
            "identity": None,
            "info": {"fieldName": "test", "parentTypeName": "Query", "variables": {}},
            "request": {"headers": {}},
        }
    )
    ok_resp = appsync.evaluate_code(
        runtime=_RUNTIME, code=_CODE, context=response_context, function="response"
    )
    assert not ok_resp.get("error"), f"unexpected error on response(): {ok_resp.get('error')}"
    assert json.loads(ok_resp["evaluationResult"]) == {"ok": True, "n": 7}, ok_resp

    context = json.dumps(
        {
            "arguments": {},
            "stash": {},
            "result": None,
            "source": None,
            "identity": None,
            "info": {"fieldName": "test", "parentTypeName": "Query", "variables": {}},
            "request": {"headers": {}},
        }
    )

    resp = appsync.evaluate_code(
        runtime=_RUNTIME, code=_CODE, context=context, function="request"
    )

    error = resp.get("error") or {}
    assert "bad-request-boom" in (error.get("message") or ""), f"unexpected: {resp}"
    assert not resp.get("evaluationResult"), f"expected no result on error: {resp}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
