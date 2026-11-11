"""evaluate-code-sandbox-isolation."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected an invalid `function` value to be rejected, but the call SUCCEEDED and "
        f"returned {result!r}"
    )

CHECK = "evaluate-code-sandbox-isolation"
GROUP = 'evaluate'
SERVICES = ['appsync']

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Each EvaluateCode call starts from fresh module state and leaves an existing GraphQL API
    unchanged; an invalid `function` value fails BadRequestException.
    """
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real-behav-check": CHECK},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    before = svc.get_graphql_api(apiId=api_id)["graphqlApi"]

    # If the sandbox reused the same engine/module instance across separate EvaluateCode
    # invocations, the second call would observe globalCounter already at 1 and report 2.
    code_src = (
        "let globalCounter = 0;\n"
        "export function request(ctx) {\n"
        "  globalCounter += 1;\n"
        "  return { counter: globalCounter };\n"
        "}\n"
        "export function response(ctx) {\n"
        "  return ctx.result;\n"
        "}\n"
    )
    context = json.dumps({"arguments": {}, "stash": {}})

    resp1 = svc.evaluate_code(
        runtime={"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"},
        code=code_src,
        context=context,
        function="request",
    )
    assert not resp1.get("error"), f"unexpected JS evaluation error: {resp1.get('error')}"
    result1 = json.loads(resp1["evaluationResult"])
    assert result1["counter"] == 1, f"expected a fresh sandbox to start globalCounter at 1, got {result1}"

    resp2 = svc.evaluate_code(
        runtime={"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"},
        code=code_src,
        context=context,
        function="request",
    )
    result2 = json.loads(resp2["evaluationResult"])
    assert result2["counter"] == 1, (
        f"expected each EvaluateCode invocation to get a fresh module-level sandbox rather than "
        f"reusing state across calls, got counter={result2['counter']}"
    )

    after = svc.get_graphql_api(apiId=api_id)["graphqlApi"]
    assert after == before, (
        f"EvaluateCode must never mutate a persisted API resource, but the API changed: "
        f"before={before!r} after={after!r}"
    )

    code, message = _error(
        lambda: svc.evaluate_code(
            runtime={"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"},
            code=code_src,
            context=context,
            function="not_a_real_function",
        )
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException for an invalid `function` value, got {code}"
    )
    assert message == 'Function must be "request", or "response"', (
        f"unexpected message for an invalid `function` value: {message!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
