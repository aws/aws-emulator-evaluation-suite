"""create-ai-benchmark-job-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-ai-benchmark-job-lifecycle"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAIBenchmarkJob whose endpoint target does not exist fails with ValidationException
    "SageMaker endpoint '<name>' does not exist", and DescribeAIBenchmarkJob then fails with
    ResourceNotFound "AIBenchmarkJob '<job>' not found.": the refused create leaves no job."""
    sm = ctx.client("sagemaker")
    role_arn = _ensure_execution_role(ctx)

    workload_config_name = ctx.unique_name("sim2real-behav-awc-")
    sm.create_ai_workload_config(
        AIWorkloadConfigName=workload_config_name,
        Tags=[{"Key": "sim2real-behav", "Value": "create-ai-benchmark-job-lifecycle"}],
    )
    ctx.on_cleanup(lambda: sm.delete_ai_workload_config(AIWorkloadConfigName=workload_config_name))

    job_name = ctx.unique_name("sim2real-behav-abj-")
    endpoint_name = ctx.unique_name("sim2real-behav-ep-")
    code, message = _error(
        lambda: _create_benchmark_job_with_role_propagation_retry(
            sm,
            AIBenchmarkJobName=job_name,
            BenchmarkTarget={"Endpoint": {"Identifier": endpoint_name}},
            OutputConfig={"S3OutputLocation": f"s3://sim2real-behav/{job_name}/output"},
            AIWorkloadConfigIdentifier=workload_config_name,
            RoleArn=role_arn,
            Tags=[{"Key": "sim2real-behav", "Value": "create-ai-benchmark-job-lifecycle"}],
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message!r}"
    expected = f"SageMaker endpoint '{endpoint_name}' does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no job exists under the refused name.
    describe_code, describe_message = _error(lambda: sm.describe_ai_benchmark_job(AIBenchmarkJobName=job_name))
    assert describe_code == "ResourceNotFound", (
        f"expected ResourceNotFound describing the refused job, got {describe_code!r}"
    )
    expected_describe = f"AIBenchmarkJob '{job_name}' not found."
    assert describe_message == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_message!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises, so a target that
    accepts a call AWS refuses fails here rather than as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"AWS refuses this call, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")


def _create_benchmark_job_with_role_propagation_retry(sm, timeout_s=90.0, interval_s=5.0, **kwargs):
    """IAM's own GetRole is strongly consistent, but a freshly created role is not yet assumable by
    sagemaker.amazonaws.com everywhere for some seconds after that; real AWS reports this as a
    ValidationException naming the RoleArn, not as a slow response. Retry on that specific
    signal rather than a fixed delay."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sm.create_ai_benchmark_job(**kwargs)
        except ClientError as exc:
            error = exc.response["Error"]
            not_yet_assumable = error["Code"] == "ValidationException" and "assume" in error.get(
                "Message", ""
            ).lower()
            if not_yet_assumable and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _ensure_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-behav", "Value": "create-ai-benchmark-job-lifecycle"}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: iam.get_role(RoleName=role_name)["Role"]["Arn"],
        lambda arn: arn == role_arn,
        timeout_s=30.0,
        interval_s=2.0,
    )
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
