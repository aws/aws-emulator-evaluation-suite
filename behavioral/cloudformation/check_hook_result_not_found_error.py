"""hook-result-not-found-error."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "hook-result-not-found-error"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetHookResult for a random, well-formed HookResultId fails with
    HookResultNotFound "The hook result was not found.": only ids issued by a Hook
    invocation resolve."""
    cfn = ctx.client("cloudformation")
    bogus_hook_result_id = str(uuid.uuid4())

    from botocore.exceptions import ClientError

    try:
        resp = cfn.get_hook_result(HookResultId=bogus_hook_result_id)
    except ClientError as err:
        error = err.response.get("Error", {})
        assert error.get("Code") == "HookResultNotFound", (
            f"expected HookResultNotFound for an unknown HookResultId, got {error!r}"
        )
        assert error.get("Message") == "The hook result was not found.", (
            f"expected message 'The hook result was not found.', got {error!r}"
        )
        return

    raise AssertionError(
        f"expected GetHookResult to reject an unknown HookResultId with "
        f"HookResultNotFound, got a 200 response instead: {resp!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
