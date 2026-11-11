"""ai-workload-config-create-delete-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ai-workload-config-create-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AIWorkloadConfig create->delete lifecycle succeeds when unreferenced and the
    resource ceases to exist afterward (Describe/Delete both return ResourceNotFound)."""
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-aiwc-")
    tags_ = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}]

    try:
        resp = sm.create_ai_workload_config(AIWorkloadConfigName=name, Tags=tags_)
    except AttributeError:
        raise AssertionError(
            "installed botocore does not expose create_ai_workload_config "
            "(SageMaker AI Workload Config API not present in this SDK version)"
        )

    arn = resp["AIWorkloadConfigArn"]

    cleaned = {"done": False}

    def _cleanup() -> None:
        if not cleaned["done"]:
            try:
                sm.delete_ai_workload_config(AIWorkloadConfigName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFound":
                    raise

    ctx.on_cleanup(_cleanup)

    desc = sm.describe_ai_workload_config(AIWorkloadConfigName=name)
    assert desc["AIWorkloadConfigArn"] == arn, (
        f"expected DescribeAIWorkloadConfig to echo the ARN {arn!r} minted by Create, got {desc.get('AIWorkloadConfigArn')!r}"
    )

    sm.delete_ai_workload_config(AIWorkloadConfigName=name)
    cleaned["done"] = True

    describe_err = _client_error(lambda: sm.describe_ai_workload_config(AIWorkloadConfigName=name))
    assert describe_err["Code"] == "ResourceNotFound", f"expected ResourceNotFound after delete, got {describe_err!r}"
    expected_describe = f"AIWorkloadConfig '{name}' not found."
    assert describe_err["Message"] == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_err.get('Message')!r}"
    )

    delete_err = _client_error(lambda: sm.delete_ai_workload_config(AIWorkloadConfigName=name))
    # message varies: the repeat-delete message embeds a per-call backend request id, the backend
    # service name and the SDK attempt count; the not-found sentence before them is graded.
    assert delete_err["Code"] == "ResourceNotFound", f"expected ResourceNotFound on repeat delete, got {delete_err!r}"
    assert delete_err["Message"].startswith(f"{expected_describe} (Service: "), (
        f"expected the repeat delete to open with {expected_describe!r}, got {delete_err.get('Message')!r}"
    )


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
