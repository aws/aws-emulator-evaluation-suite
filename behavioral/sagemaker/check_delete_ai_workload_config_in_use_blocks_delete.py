"""delete-ai-workload-config-in-use-blocks-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-ai-workload-config-in-use-blocks-delete"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAIWorkloadConfig removes a live config: DescribeAIWorkloadConfig then returns
    ResourceNotFound with its exact message, and a second delete returns ResourceNotFound with a
    message that starts with the same text.
    """
    sm = ctx.client("sagemaker")
    config_name = ctx.unique_name("sim2real-aiwc-")[:63]

    sm.create_ai_workload_config(AIWorkloadConfigName=config_name)
    ctx.on_cleanup(lambda: _safe_delete_config(sm, config_name))

    described = sm.describe_ai_workload_config(AIWorkloadConfigName=config_name)
    assert described["AIWorkloadConfigArn"], "expected a non-empty AIWorkloadConfigArn on create"

    sm.delete_ai_workload_config(AIWorkloadConfigName=config_name)

    # Effect present: the config is actually gone.
    describe_code, describe_message = _error(
        lambda: sm.describe_ai_workload_config(AIWorkloadConfigName=config_name)
    )
    assert describe_code == "ResourceNotFound", f"expected ResourceNotFound, got {describe_code}"
    expected = f"AIWorkloadConfig '{config_name}' not found."
    assert describe_message == expected, f"expected {expected!r}, got {describe_message!r}"

    # A second delete of the deleted config also returns ResourceNotFound,
    # not a silent no-op success.
    code_again, message_again = _error(
        lambda: sm.delete_ai_workload_config(AIWorkloadConfigName=config_name)
    )
    # message varies: the repeat-delete message embeds a per-request id, the backend service name
    # and the SDK attempt count; the not-found sentence before them is graded.
    assert code_again == "ResourceNotFound", f"expected ResourceNotFound, got {code_again}"
    assert (message_again or "").startswith(f"{expected} (Service: "), (
        f"expected the repeat delete to open with {expected!r}, got {message_again!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_config(sm, name):
    try:
        sm.delete_ai_workload_config(AIWorkloadConfigName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
