"""evaluate-code-success."""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "evaluate-code-success"
GROUP = "evaluate"
SERVICES = ["appsync"]

# Prefix of the failure detail raised when EvaluateCode does not run the APPSYNC_JS code: a target
# with no JS engine answers a ClientError naming an unsupported runtime or an empty
# evaluationResult, and that is a data-plane miss, not a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """EvaluateCode executes an APPSYNC_JS request handler and returns its return value as evaluationResult."""
    svc = ctx.client("appsync")
    code = (
        "export function request(ctx) {\n"
        "  return { result: ctx.args.id };\n"
        "}\n"
        "export function response(ctx) {\n"
        "  return ctx.result;\n"
        "}\n"
    )
    context = json.dumps({"arguments": {"id": "xyz-789"}, "args": {"id": "xyz-789"}})

    try:
        resp = svc.evaluate_code(
            runtime={"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"},
            code=code,
            context=context,
            function="request",
        )
    except ClientError as exc:
        # The engine is the data plane here: a target that cannot run APPSYNC_JS rejects the call
        # rather than returning a wrong answer, and that refusal is the fidelity verdict.
        raise AssertionError(
            f"{DATAPLANE_MARKER}: evaluate_code refused: {exc}"
        ) from exc
    assert not resp.get("error"), f"{DATAPLANE_MARKER}: {resp.get('error')}"

    raw = resp.get("evaluationResult")
    assert raw, f"{DATAPLANE_MARKER}: no evaluationResult returned: {resp!r}"
    result = json.loads(raw)
    assert result == {"result": "xyz-789"}, f"expected {{'result': 'xyz-789'}}, got {result!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
