"""create-hyper-parameter-tuning-job-out-of-range-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-hyper-parameter-tuning-job-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateHyperParameterTuningJob rejects a ContinuousParameterRange whose MinValue
    exceeds its MaxValue rather than accepting it and deferring to launch time; a
    tuning job with a valid (Min < Max) range (the positive control) still succeeds."""
    # The positive control launches a short-lived tuning job; CreateHyperParameterTuningJob checks
    # that the role can pull the training image, so it uses AWS's linear-learner container, and the
    # job fails almost at once (nonexistent output bucket) without real training work.
    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_exec_role(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    image = f"382416733822.dkr.ecr.{ctx.region}.amazonaws.com/linear-learner:1"
    output_s3 = f"s3://sim2real-nonexistent-bucket-{account_id}/tuning-output"

    def _training_job_definition() -> dict:
        return {
            "AlgorithmSpecification": {
                "TrainingImage": image,
                "TrainingInputMode": "File",
                "MetricDefinitions": [
                    {"Name": "validation:error", "Regex": r"validation:error.*=\s*([0-9.]+)"}
                ],
            },
            "RoleArn": role_arn,
            "OutputDataConfig": {"S3OutputPath": output_s3},
            "ResourceConfig": {
                "InstanceType": "ml.m5.large",
                "InstanceCount": 1,
                "VolumeSizeInGB": 10,
            },
            "StoppingCondition": {"MaxRuntimeInSeconds": 600},
        }

    def _tuning_config(min_value: str, max_value: str) -> dict:
        return {
            "Strategy": "Bayesian",
            "HyperParameterTuningJobObjective": {
                "Type": "Minimize",
                "MetricName": "validation:error",
            },
            "ResourceLimits": {"MaxNumberOfTrainingJobs": 1, "MaxParallelTrainingJobs": 1},
            "ParameterRanges": {
                "ContinuousParameterRanges": [
                    {"Name": "eta", "MinValue": min_value, "MaxValue": max_value}
                ]
            },
        }

    # --- negative: MinValue (1.0) > MaxValue (0.5) ---
    bad_job_name = ctx.unique_name("sim2real-bad-hpo-")
    code, message = _rejection_once_role_is_assumable(
        lambda: sm.create_hyper_parameter_tuning_job(
            HyperParameterTuningJobName=bad_job_name,
            HyperParameterTuningJobConfig=_tuning_config("1.0", "0.5"),
            TrainingJobDefinition=_training_job_definition(),
        ),
        timeout_s=90,
    )
    assert code == "ValidationException", f"expected ValidationException, got {code} ({message!r})"
    expected_message = (
        "The hyperparameter ranges [eta] are not valid. For continuous parameter ranges, the "
        "value of MinValue must be smaller than the value of MaxValue. Specify a value for "
        "MinValue that is smaller than the value of MaxValue."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no tuning job was created under that name
    describe_code, describe_message = _error_code_and_message(
        lambda: sm.describe_hyper_parameter_tuning_job(
            HyperParameterTuningJobName=bad_job_name
        )
    )
    assert describe_code == "ResourceNotFound", (
        f"expected DescribeHyperParameterTuningJob to fail for a job that was never "
        f"created, got {describe_code}"
    )
    expected_describe = f"Amazon SageMaker can't find a tuning job called {bad_job_name}. Type another name."
    assert describe_message == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_message!r}"
    )

    # --- positive control: MinValue (0.1) < MaxValue (0.5) succeeds; a call made before the new
    # role propagates fails with a ValidationException naming the role, which is retried to a deadline.
    good_job_name = ctx.unique_name("sim2real-good-hpo-")
    resp = _retry_role_not_yet_propagated(
        lambda: sm.create_hyper_parameter_tuning_job(
            HyperParameterTuningJobName=good_job_name,
            HyperParameterTuningJobConfig=_tuning_config("0.1", "0.5"),
            TrainingJobDefinition=_training_job_definition(),
            Tags=[{"Key": "sim2real", "Value": "1"}],
        ),
        timeout_s=60,
    )
    assert resp["HyperParameterTuningJobArn"]
    ctx.on_cleanup(lambda: _stop_tuning_job_best_effort(sm, good_job_name))

    described = sm.describe_hyper_parameter_tuning_job(
        HyperParameterTuningJobName=good_job_name
    )
    assert described["HyperParameterTuningJobStatus"] in ("InProgress", "Completed", "Failed")


# ===== helpers =====
def _error_code_and_message(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so an
    over-permissive target fails as such rather than as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


# A freshly created execution role is refused with this exact message until SageMaker can
# assume it; only that propagation refusal is retried, never the rejection under test.
_ROLE_NOT_YET_ASSUMABLE = (
    "SageMaker is unable to perform: sts:AssumeRole on the role. Check if you have a trust "
    "relationship for 'sagemaker.amazonaws.com' to assume the role."
)


def _rejection_once_role_is_assumable(fn, *, timeout_s: float, interval_s: float = 5.0):
    """Return fn()'s (code, message) once the rejection is no longer the role-propagation
    refusal; a still-unassumable role past the deadline is returned as-is and fails the
    caller's exact-message assertion."""
    deadline = time.monotonic() + timeout_s
    while True:
        code, message = _error_code_and_message(fn)
        if (
            code == "ValidationException"
            and message == _ROLE_NOT_YET_ASSUMABLE
            and time.monotonic() < deadline
        ):
            time.sleep(interval_s)
            continue
        return code, message


def _retry_role_not_yet_propagated(fn, *, timeout_s: float, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            error = exc.response["Error"]
            if (
                error["Code"] == "ValidationException"
                and "role" in error.get("Message", "").lower()
                and time.monotonic() < deadline
            ):
                time.sleep(interval_s)
                continue
            raise


def _create_sagemaker_exec_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    arn = resp["Role"]["Arn"]
    for _ in range(10):
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(1)
    return arn


def _stop_tuning_job_best_effort(sm, job_name: str) -> None:
    try:
        sm.stop_hyper_parameter_tuning_job(HyperParameterTuningJobName=job_name)
    except ClientError as exc:
        # ValidationException: the job already reached a terminal status.
        if exc.response["Error"]["Code"] not in ("ResourceNotFound", "ValidationException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
