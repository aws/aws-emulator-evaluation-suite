"""delete-ai-workload-config-idempotent-not-found-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-ai-workload-config-idempotent-not-found-rejected"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteAIWorkloadConfig, DescribeAIWorkloadConfig returns ResourceNotFound with its exact message and
    a second delete of the same name also returns ResourceNotFound, so a delete does not succeed twice.
    """
    sm = ctx.client("sagemaker")
    config_name = ctx.unique_name("sim2real-behav-awc-")

    create_resp = sm.create_ai_workload_config(
        AIWorkloadConfigName=config_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    config_arn = create_resp["AIWorkloadConfigArn"]
    ctx.on_cleanup(lambda: _delete_if_present(sm, config_name))

    described = sm.describe_ai_workload_config(AIWorkloadConfigName=config_name)
    assert described["AIWorkloadConfigArn"] == config_arn, (
        f"expected describe to echo the created ARN {config_arn!r}, got {described.get('AIWorkloadConfigArn')!r}"
    )

    sm.delete_ai_workload_config(AIWorkloadConfigName=config_name)

    code, message = _error(lambda: sm.describe_ai_workload_config(AIWorkloadConfigName=config_name))
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code!r}"
    expected = f"AIWorkloadConfig '{config_name}' not found."
    assert message == expected, f"expected {expected!r}, got {message!r}"

    repeat_code, _repeat_message = _error(lambda: sm.delete_ai_workload_config(AIWorkloadConfigName=config_name))
    # message varies: the repeat-delete message embeds a per-request id.
    assert repeat_code == "ResourceNotFound", f"expected ResourceNotFound on repeat delete, got {repeat_code!r}"


def _delete_if_present(sm, name):
    from botocore.exceptions import ClientError

    try:
        sm.delete_ai_workload_config(AIWorkloadConfigName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ResourceNotFound rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
