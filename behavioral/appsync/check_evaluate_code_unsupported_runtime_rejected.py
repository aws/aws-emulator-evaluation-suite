"""evaluate-code-unsupported-runtime-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "evaluate-code-unsupported-runtime-rejected"
GROUP = 'evaluate'
SERVICES = ['appsync']

_CODE = (
    "export function request(ctx) { return {}; }\n"
    "export function response(ctx) { return ctx.result; }\n"
)
_CONTEXT = '{"arguments": {}}'


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Only the APPSYNC_JS runtime exists; an unknown runtime name must be rejected
    at the API boundary rather than silently accepted."""
    appsync = ctx.client("appsync")

    # Positive control: the identical call with the one real runtime name succeeds,
    # so a target that simply rejects every evaluate_code call cannot pass this check.
    control = appsync.evaluate_code(
        runtime={"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"},
        code=_CODE,
        context=_CONTEXT,
        function="request",
    )
    assert not control.get("error") and control.get("evaluationResult"), (
        f"positive control failed: expected a clean evaluation, got {control!r}"
    )

    # Break exactly one thing: swap in a runtime name the service has never modelled.
    try:
        appsync.evaluate_code(
            runtime={"name": "NOT_A_RUNTIME", "runtimeVersion": "1.0.0"},
            code=_CODE,
            context=_CONTEXT,
            function="request",
        )
    except ClientError as exc:
        err = exc.response.get("Error", {})
        code, message = err.get("Code"), err.get("Message")
        assert code == "BadRequestException", f"unexpected code {code}"
        assert message == (
            "1 validation error detected: Value at 'runtime.name' failed to satisfy constraint: "
            "Member must satisfy enum value set: [APPSYNC_JS]"
        ), f"unexpected message {message!r}"
        return
    raise AssertionError("expected an unsupported runtime to be rejected")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
