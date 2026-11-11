"""op-contract-evaluateCode."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "op-contract-evaluateCode"
GROUP = "error-semantics"
SERVICES = ["appsync"]

_RUNTIME = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}
_GOOD_CODE = (
    "export function request(ctx) {\n"
    "  return { payload: ctx.arguments.id };\n"
    "}\n"
    "\n"
    "export function response(ctx) {\n"
    "  return ctx.result;\n"
    "}\n"
)
_BAD_CODE = (
    "export function request(ctx) {\n"
    "  retun ctx.arguments.id;\n"  # deliberate syntax typo ("retun")
    "}\n"
    "\n"
    "export function response(ctx) {\n"
    "  return ctx.result;\n"
    "}\n"
)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """EvaluateCode: success contract (evaluationResult), and on a compile error an HTTP 200
    with a structured error object in the body and no evaluationResult (no error code)."""
    appsync = ctx.client("appsync")
    context = json.dumps(
        {
            "arguments": {"id": "widget-1"},
            "stash": {},
            "result": None,
            "source": None,
            "identity": None,
            "info": {"fieldName": "test", "parentTypeName": "Query", "variables": {}},
            "request": {"headers": {}},
        }
    )

    resp = appsync.evaluate_code(
        runtime=_RUNTIME, code=_GOOD_CODE, context=context, function="request"
    )
    assert resp.get("error") in (None, {}), f"unexpected evaluation error: {resp.get('error')}"
    result = json.loads(resp["evaluationResult"])
    assert result == {"payload": "widget-1"}, f"unexpected evaluationResult: {result}"

    # Error boundary: code with a syntax error fails to compile. On real AWS, EvaluateCode
    # does NOT raise a ClientError for this -- it returns HTTP 200 with the compile failure
    # surfaced in resp["error"] and no usable evaluationResult. Assert that error-in-body
    # contract instead of a (non-existent) BadRequestException.
    bad_resp = appsync.evaluate_code(
        runtime=_RUNTIME, code=_BAD_CODE, context=context, function="request"
    )
    error = bad_resp.get("error")
    assert error, f"expected a compile error to be reported, got: {bad_resp}"
    assert isinstance(error, dict) and error.get("message"), (
        f"expected a structured error object with a message, got: {error!r}"
    )
    assert not bad_resp.get("evaluationResult"), (
        f"unexpected evaluationResult alongside error: {bad_resp}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
