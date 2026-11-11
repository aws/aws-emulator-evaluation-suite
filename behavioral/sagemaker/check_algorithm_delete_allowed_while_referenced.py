"""algorithm-delete-allowed-while-referenced."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "algorithm-delete-allowed-while-referenced"
GROUP = "state-machine"
SERVICES = ["sagemaker"]

_TAGS = [{"Key": "sim2real-behav-check", "Value": CHECK}]

# SageMaker's built-in-algorithm ECR images are pullable by any account, so CreateAlgorithm's
# registry-access check succeeds without pushing an image; account IDs are the per-Region
# built-in-algorithm registries.
_BUILTIN_ALGO_ACCOUNT_BY_REGION = {
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
    "eu-west-1": "685385470294",
    "eu-central-1": "664544806723",
    "ap-southeast-1": "475088953585",
    "ap-southeast-2": "712309505854",
    "ap-northeast-1": "351501993468",
    "ap-south-1": "991648021394",
    "ca-central-1": "469771592824",
}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAlgorithm succeeds while a running TrainingJob references the algorithm; Describe and a
    second delete then raise ValidationException "does not exist", and the job stays describable.
    An unreferenced control algorithm deletes with the same outcome.
    """
    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_training_role(ctx)
    bucket = _create_output_bucket(ctx)
    account = _BUILTIN_ALGO_ACCOUNT_BY_REGION.get(ctx.region)
    if account is None:
        raise AssertionError(f"no known built-in-algorithm ECR registry account for region {ctx.region}")
    image = f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/linear-learner:1"

    algo_name = ctx.unique_name("sim2real-behav-algo-")
    algo_arn = _create_algorithm(sm, algo_name, image)
    ctx.on_cleanup(lambda: _delete_algorithm_best_effort(sm, algo_name))
    _wait_algorithm_completed(sm, algo_name)

    job_name = ctx.unique_name("sim2real-behav-train-")
    _retry_role_propagation(
        lambda: sm.create_training_job(
            TrainingJobName=job_name,
            AlgorithmSpecification={"AlgorithmName": algo_name, "TrainingInputMode": "File"},
            RoleArn=role_arn,
            ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 1},
            OutputDataConfig={"S3OutputPath": f"s3://{bucket}/output"},
            StoppingCondition={"MaxRuntimeInSeconds": 120},
            Tags=_TAGS,
        )
    )
    ctx.on_cleanup(lambda: _stop_training_job_best_effort(sm, job_name))

    status = sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"]
    assert status == "InProgress", f"expected training job to start InProgress, got {status}"

    # wait past "Starting" so the job is genuinely pulling the algorithm's container --
    # not merely queued -- before we test whether the reference blocks the delete
    _wait_secondary_status_at_least_downloading(sm, job_name, timeout_s=300.0)

    # SageMaker does not treat a live TrainingJob as a delete-blocking dependency.
    sm.delete_algorithm(AlgorithmName=algo_name)

    # DescribeAlgorithm reports a deleted algorithm as ValidationException("... does not exist."),
    # not the ResourceNotFound used elsewhere in the SageMaker API.
    gone_code, gone_message = _error_code_and_message(lambda: sm.describe_algorithm(AlgorithmName=algo_name))
    gone_expected = f"Algorithm {algo_arn} does not exist."
    assert gone_code == "ValidationException" and gone_message == gone_expected, (
        f"expected ValidationException {gone_expected!r}, got {gone_code}: {gone_message}"
    )

    # A second delete must fail rather than succeed again regardless of state.
    redelete_code, redelete_message = _error_code_and_message(
        lambda: sm.delete_algorithm(AlgorithmName=algo_name)
    )
    assert redelete_code == "ValidationException" and redelete_message == gone_expected, (
        f"expected re-deleting an already-deleted algorithm to report ValidationException "
        f"{gone_expected!r}, got {redelete_code}: {redelete_message}"
    )

    # The job outlives its algorithm: still describable and still naming it. Its status is its own
    # run's (it has no input channel and a 120 s budget), so any modeled status is accepted.
    job_after = sm.describe_training_job(TrainingJobName=job_name)
    assert job_after["AlgorithmSpecification"].get("AlgorithmName") in (algo_name, algo_arn), (
        f"expected the training job to keep naming its deleted algorithm, got "
        f"{job_after['AlgorithmSpecification']!r}"
    )
    assert job_after["TrainingJobStatus"] in ("InProgress", "Completed", "Failed", "Stopping", "Stopped"), (
        f"expected the training job to stay describable after its algorithm was deleted, "
        f"got {job_after['TrainingJobStatus']}"
    )

    # Control: an algorithm that was never referenced.
    control_name = ctx.unique_name("sim2real-behav-algo-ctrl-")
    control_arn = _create_algorithm(sm, control_name, image)
    _wait_algorithm_completed(sm, control_name)
    sm.delete_algorithm(AlgorithmName=control_name)
    control_code, control_message = _error_code_and_message(
        lambda: sm.describe_algorithm(AlgorithmName=control_name)
    )
    control_expected = f"Algorithm {control_arn} does not exist."
    assert control_code == "ValidationException" and control_message == control_expected, (
        f"expected the unreferenced control algorithm to be gone with ValidationException "
        f"{control_expected!r}, got {control_code}: {control_message}"
    )


# ===== helpers =====

def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _create_sagemaker_training_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=_TAGS
    )
    role_arn = resp["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        for call in (
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn),
            lambda: iam.delete_role(RoleName=role_name),
        ):
            try:
                call()
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                    raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_output_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-out-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})

    def _cleanup():
        # A stopping training job can still upload output, so retry an emptied bucket that refills.
        deadline = time.monotonic() + 60.0
        while True:
            try:
                for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
                    s3.delete_object(Bucket=bucket, Key=obj["Key"])
                s3.delete_bucket(Bucket=bucket)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "NoSuchBucket":
                    return
                if code != "BucketNotEmpty" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_algorithm(sm, name, image):
    return sm.create_algorithm(
        AlgorithmName=name,
        TrainingSpecification={
            "TrainingImage": image,
            "SupportedTrainingInstanceTypes": ["ml.m5.large"],
            "TrainingChannels": [
                {
                    "Name": "training",
                    "IsRequired": False,
                    "SupportedContentTypes": ["text/csv"],
                    "SupportedInputModes": ["File"],
                }
            ],
        },
        Tags=_TAGS,
    )["AlgorithmArn"]


def _wait_secondary_status_at_least_downloading(sm, job_name, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    secondary = None
    while time.monotonic() < deadline:
        desc = sm.describe_training_job(TrainingJobName=job_name)
        secondary = desc["SecondaryStatus"]
        if secondary in ("Downloading", "DownloadingTrainingImage", "Training", "Uploading"):
            return secondary
        status = desc["TrainingJobStatus"]
        if status != "InProgress":
            raise AssertionError(
                f"training job {job_name} left InProgress (status={status}, "
                f"secondary={secondary}) before reaching an active-container phase"
            )
        time.sleep(interval_s)
    raise TimeoutError(
        f"training job {job_name} did not reach an active-container phase within "
        f"{timeout_s}s, last saw secondary status {secondary}"
    )


def _wait_algorithm_completed(sm, name, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = sm.describe_algorithm(AlgorithmName=name)["AlgorithmStatus"]
        if status == "Completed":
            return
        if status == "Failed":
            raise AssertionError(f"algorithm {name} validation failed instead of completing")
        time.sleep(interval_s)
    raise TimeoutError(f"algorithm {name} did not reach Completed status, last saw {status}")


def _retry_role_propagation(fn, timeout_s=30.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("AccessDeniedException", "ValidationException"):
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _delete_algorithm_best_effort(sm, name):
    try:
        sm.delete_algorithm(AlgorithmName=name)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") != "ValidationException" or "does not exist" not in err.get("Message", ""):
            raise


def _stop_training_job_best_effort(sm, job_name):
    try:
        sm.stop_training_job(TrainingJobName=job_name)
    except ClientError as exc:
        # ValidationException: the job already reached a terminal status.
        if exc.response.get("Error", {}).get("Code") not in ("ResourceNotFound", "ValidationException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
