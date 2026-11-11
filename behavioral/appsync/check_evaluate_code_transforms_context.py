"""evaluate-code-transforms-context."""
from __future__ import annotations

import json

from behavioral_harness import tags


CHECK = "evaluate-code-transforms-context"
GROUP = "data-plane"
SERVICES = ["appsync"]

VALID_CODE = (
    "export function request(ctx) {\n"
    "  return ctx.args.value * 2;\n"
    "}\n"
    "export function response(ctx) {\n"
    "  return ctx.result;\n"
    "}\n"
)

BROKEN_CODE = (
    "export function request(ctx) {\n"
    "  return ctx.args.value *\n"  # syntax error: dangling operator
)

REQUEST_ONLY_CODE = (
    "export function request(ctx) {\n"
    "  return ctx.args.value * 2;\n"
    "}\n"
)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """EvaluateCode runs an APPSYNC_JS handler against the given context and returns the computed
    result; code with a syntax error, or missing the response export, returns an error and no result."""
    appsync = ctx.client("appsync")
    runtime = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}
    context = json.dumps({"arguments": {"value": 21}})

    resp = appsync.evaluate_code(
        runtime=runtime, code=VALID_CODE, context=context, function="request"
    )
    assert resp.get("error") is None, resp.get("error")
    result = json.loads(resp["evaluationResult"])
    assert result == 42, f"expected 42, got {result}"

    bad_resp = appsync.evaluate_code(
        runtime=runtime, code=BROKEN_CODE, context=context, function="request"
    )
    error = bad_resp.get("error") or {}
    assert error, f"broken JS handler should be rejected via an `error` field, got {bad_resp}"
    code_errors = error.get("codeErrors") or []
    assert code_errors, f"expected structured codeErrors for a syntax error, got {error!r}"
    assert not bad_resp.get("evaluationResult"), (
        f"broken JS handler must not produce a usable evaluationResult: {bad_resp}"
    )

    incomplete_resp = appsync.evaluate_code(
        runtime=runtime, code=REQUEST_ONLY_CODE, context=context, function="request"
    )
    incomplete_error = incomplete_resp.get("error") or {}
    assert incomplete_error, (
        f"a module missing response() should be rejected even when evaluating only "
        f"request(), got {incomplete_resp}"
    )
    incomplete_code_errors = incomplete_error.get("codeErrors") or []
    error_types = {e.get("errorType") for e in incomplete_code_errors}
    assert "MISSING_MAPPING_EXPORT" in error_types, (
        f"expected a MISSING_MAPPING_EXPORT codeError for a module missing response(), "
        f"got codeErrors={incomplete_code_errors!r}"
    )
    assert not incomplete_resp.get("evaluationResult"), (
        f"module missing response() must not produce a usable evaluationResult: {incomplete_resp}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
