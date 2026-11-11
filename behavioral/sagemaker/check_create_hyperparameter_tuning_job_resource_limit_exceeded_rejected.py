"""create-hyperparameter-tuning-job-resource-limit-exceeded-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-hyperparameter-tuning-job-resource-limit-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateHyperParameterTuningJob with ResourceLimits far beyond the parallel-training-job
    quota is rejected up front with ResourceLimitExceeded naming it; a tiny limit succeeds."""
    role_arn = _create_sagemaker_role(ctx)
    sm = ctx.client("sagemaker")
    # CreateHyperParameterTuningJob checks that the training image is pullable and the input bucket
    # has objects under the prefix; SageMaker's built-in-algorithm registries are AWS-owned per
    # region (us-west-2 linear-learner: 174872318107).
    training_image = f"174872318107.dkr.ecr.{ctx.region}.amazonaws.com/linear-learner:1"
    bucket = _create_input_bucket(ctx)

    training_job_definition = {
        "AlgorithmSpecification": {
            "TrainingImage": training_image,
            "TrainingInputMode": "File",
        },
        "RoleArn": role_arn,
        "InputDataConfig": [
            {
                "ChannelName": "train",
                "DataSource": {
                    "S3DataSource": {
                        "S3DataType": "S3Prefix",
                        "S3Uri": f"s3://{bucket}/train",
                        "S3DataDistributionType": "FullyReplicated",
                    }
                },
            }
        ],
        "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/out"},
        "ResourceConfig": {
            "InstanceType": "ml.m5.large",
            "InstanceCount": 1,
            "VolumeSizeInGB": 30,
        },
        "StoppingCondition": {"MaxRuntimeInSeconds": 600},
    }
    tuning_objective = {"Type": "Minimize", "MetricName": "test:objective_loss"}
    # linear-learner's tunable hyperparameters are a fixed, named set server-side;
    # learning_rate is one of them.
    parameter_ranges = {
        "ContinuousParameterRanges": [
            {"Name": "learning_rate", "MinValue": "0.0001", "MaxValue": "0.1"}
        ]
    }

    bad_name = ctx.unique_name("sim2real-badtune-")
    code, message = _rejection_once_role_is_assumable(
        lambda: sm.create_hyper_parameter_tuning_job(
            HyperParameterTuningJobName=bad_name,
            HyperParameterTuningJobConfig={
                "Strategy": "Random",
                "HyperParameterTuningJobObjective": tuning_objective,
                "ResourceLimits": {
                    "MaxParallelTrainingJobs": 999999999,
                    "MaxNumberOfTrainingJobs": 999999999,
                },
                "ParameterRanges": parameter_ranges,
            },
            TrainingJobDefinition=training_job_definition,
        ),
        timeout_s=90,
    )
    assert code == "ResourceLimitExceeded", f"expected ResourceLimitExceeded, got {code} ({message!r})"
    expected_message = (
        "The account-level service limit 'Maximum number of training jobs each hyper "
        "parameter tuning job can run in parallel at once' is 10 TrainingJobs, with current "
        "utilization of 0 TrainingJobs and a request delta of 999999999 TrainingJobs. Please "
        "use AWS Service Quotas to request an increase for this quota. If AWS Service Quotas "
        "is not available, contact AWS support to request an increase for this quota."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    absent_code, absent_message = _error_code_and_message(
        lambda: sm.describe_hyper_parameter_tuning_job(HyperParameterTuningJobName=bad_name)
    )
    assert absent_code == "ResourceNotFound", f"expected ResourceNotFound, got {absent_code}"
    expected_absent = f"Amazon SageMaker can't find a tuning job called {bad_name}. Type another name."
    assert absent_message == expected_absent, (
        f"expected message {expected_absent!r}, got {absent_message!r}"
    )

    good_name = ctx.unique_name("sim2real-goodtune-")

    def _stop_good():
        from botocore.exceptions import ClientError

        try:
            sm.stop_hyper_parameter_tuning_job(HyperParameterTuningJobName=good_name)
        except ClientError as exc:
            # ValidationException: the job is already stopping or terminal.
            if exc.response["Error"]["Code"] not in ("ResourceNotFound", "ValidationException"):
                raise

    ctx.on_cleanup(_stop_good)
    _create_tuning_job_with_retry(
        sm,
        HyperParameterTuningJobName=good_name,
        HyperParameterTuningJobConfig={
            "Strategy": "Random",
            "HyperParameterTuningJobObjective": tuning_objective,
            "ResourceLimits": {"MaxParallelTrainingJobs": 1, "MaxNumberOfTrainingJobs": 1},
            "ParameterRanges": parameter_ranges,
        },
        TrainingJobDefinition=training_job_definition,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    described = sm.describe_hyper_parameter_tuning_job(HyperParameterTuningJobName=good_name)
    assert described["HyperParameterTuningJobName"] == good_name, (
        f"expected HyperParameterTuningJobName {good_name!r}, "
        f"got {described.get('HyperParameterTuningJobName')!r}"
    )
    # Immediately stop to avoid burning real training compute time/cost.
    sm.stop_hyper_parameter_tuning_job(HyperParameterTuningJobName=good_name)


def _error_code_and_message(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so an
    over-permissive target fails as such rather than as a code mismatch."""
    from botocore.exceptions import ClientError

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


def _create_input_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-hpo-in-")
    if ctx.region == "us-east-1":  # S3 rejects an explicit LocationConstraint for this one region
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_object(Bucket=bucket, Key="train/data.csv", Body=b"0,1,2\n1,3,4\n")

    def _cleanup():
        from botocore.exceptions import ClientError

        # A stopping training job can still upload output, so retry an emptied bucket that refills.
        deadline = time.monotonic() + 60.0
        while True:
            try:
                for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
                    s3.delete_object(Bucket=bucket, Key=obj["Key"])
                s3.delete_bucket(Bucket=bucket)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "NoSuchBucket":
                    return
                if code != "BucketNotEmpty" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-smrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _wait_for_policy_attached(iam, role_name, policy_arn)
    return role["Arn"]


def _wait_for_policy_attached(iam, role_name, policy_arn, timeout_s=30.0):
    """Bounded poll for IAM's own read-after-write consistency on the attached policy.
    SageMaker's separate, cross-service propagation delay beyond this is absorbed by
    the AccessDeniedException retry in _create_tuning_job_with_retry."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
        if any(p["PolicyArn"] == policy_arn for p in attached):
            return
        time.sleep(2)
    raise TimeoutError(f"{policy_arn} not visible as attached to {role_name} after {timeout_s}s")


def _create_tuning_job_with_retry(sm, timeout_s=45.0, **kwargs):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sm.create_hyper_parameter_tuning_job(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            last_err = err
            if code in ("AccessDeniedException", "ValidationException"):
                time.sleep(3)
                continue
            raise
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
