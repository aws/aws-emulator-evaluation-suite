"""evaluate-code-invalid-syntax-error-detail."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "evaluate-code-invalid-syntax-error-detail"
GROUP = "server-side"
SERVICES = ["appsync"]

_RUNTIME = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}

_VALID_CODE = """
export function request(ctx) {
  return {};
}

export function response(ctx) {
  return ctx.result;
}
"""

# Deliberately unbalanced braces: the JS parser cannot even produce an AST for this.
_INVALID_CODE = """
export function request(ctx) {
  return {};
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """EvaluateCode evaluates valid JS; syntactically broken JS returns HTTP 200 with an error object
    carrying per-error line/column locations and no evaluationResult."""
    appsync = ctx.client("appsync")

    # Positive control 1: request() handler on trivial valid code returns evaluationResult.
    ok_request = appsync.evaluate_code(
        runtime=_RUNTIME, code=_VALID_CODE, context="{}", function="request"
    )
    assert not ok_request.get("error"), f"unexpected error on valid code: {ok_request.get('error')}"
    assert json.loads(ok_request["evaluationResult"]) == {}

    # Positive control 2: response() handler echoes ctx.result through evaluationResult,
    # proving the evaluator actually ran the code against the supplied context.
    ctx_json = json.dumps({"result": {"ok": True, "n": 7}})
    ok_response = appsync.evaluate_code(
        runtime=_RUNTIME, code=_VALID_CODE, context=ctx_json, function="response"
    )
    assert not ok_response.get("error")
    assert json.loads(ok_response["evaluationResult"]) == {"ok": True, "n": 7}

    # Negative: syntactically invalid code is not rejected with a client error at the
    # API level; instead EvaluateCode returns HTTP 200 with a populated top-level
    # "error" object carrying structured per-error location (line/column) diagnostics,
    # and no evaluationResult.
    bad = appsync.evaluate_code(
        runtime=_RUNTIME, code=_INVALID_CODE, context="{}", function="request"
    )
    assert not bad.get("evaluationResult"), (
        f"expected no evaluationResult for syntactically invalid code, got {bad.get('evaluationResult')!r}"
    )
    detail = bad.get("error") or {}
    assert detail, f"expected a populated error object for syntactically invalid code, got {bad!r}"
    code_errors = detail.get("codeErrors") or []
    assert len(code_errors) >= 1, f"expected at least one structured code error, got {detail!r}"
    first = code_errors[0]
    assert first.get("errorType") == "PARSE_ERROR", (
        f"expected a PARSE_ERROR code error for unbalanced braces, got: {first!r}"
    )
    location = first.get("location") or {}
    assert isinstance(location.get("line"), int) and location["line"] >= 1, (
        f"code error missing a valid source line diagnostic: {first!r}"
    )
    assert isinstance(location.get("column"), int) and location["column"] >= 1, (
        f"code error missing a valid source column diagnostic: {first!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
