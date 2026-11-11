"""update-service-job-on-terminal-job-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-service-job-on-terminal-job-rejected"
GROUP = "state-machine"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateServiceJob against a service job already in a terminal (FAILED) state is
    refused with ClientException and schedulingPriority is left unchanged; the identical
    call on a still-active job (positive control) succeeds."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    batch = ctx.client("batch")
    role_arn = _create_sagemaker_execution_role(ctx)
    bucket = _create_output_bucket(ctx)
    queue_arn, _env_arn = _create_sagemaker_queue(ctx, teardown_deadline)

    job_name = ctx.unique_name("sim2real-svcjob-")
    payload = _service_job_payload(ctx, job_name, role_arn, bucket, max_runtime=300)
    job_id = _submit_service_job_with_retry(
        batch,
        jobName=job_name,
        jobQueue=queue_arn,
        serviceJobType="SAGEMAKER_TRAINING",
        serviceRequestPayload=payload,
        schedulingPriority=1,
        # The queue has a fairshare scheduling policy attached, and real AWS Batch
        # requires every job submitted to such a queue to carry a shareIdentifier.
        shareIdentifier="default",
    )["jobId"]

    # Positive control: updating an active (non-terminal) job succeeds.
    batch.update_service_job(jobId=job_id, schedulingPriority=42)
    assert batch.describe_service_job(jobId=job_id)["schedulingPriority"] == 42

    # Break exactly one precondition: force the job into a terminal state.
    batch.terminate_service_job(jobId=job_id, reason="force-terminal-for-negative-test")
    _poll_until(
        lambda: batch.describe_service_job(jobId=job_id)["status"],
        lambda s: s == "FAILED",
        timeout_s=180,
    )

    code, message = _error_code(lambda: batch.update_service_job(jobId=job_id, schedulingPriority=9999))
    assert code == "ClientException", f"expected ClientException, got {code!r}"
    expected = "UpdateServiceJob cannot be called on a service job which is completed."
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # The forbidden effect did not happen: schedulingPriority is unchanged from before the
    # rejected call (still 42, not 9999).
    unchanged = batch.describe_service_job(jobId=job_id)
    assert unchanged["schedulingPriority"] == 42
    assert unchanged["status"] == "FAILED"


def _error_code(fn: Callable[[], Any]):
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises,
    because accepting a call real AWS refuses must not be reported as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _quietly(fn: Callable[[], Any]) -> None:
    """Best-effort cleanup call: a ClientError (already gone, still in use) is ignored."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] != "NoSuchEntity"
            and not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""))
        ):
            raise


def _submit_service_job_with_retry(batch, *, timeout_s=60.0, interval_s=5.0, **kwargs):
    from botocore.exceptions import ClientError

    # A freshly created IAM role can take a few seconds to propagate before Batch/SageMaker
    # can validate/assume it; retry the actual submission on ClientException within a bounded
    # window instead of guessing a fixed propagation delay.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return batch.submit_service_job(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ClientException":
                raise
            last_exc = e
            time.sleep(interval_s)
    raise last_exc


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_sagemaker_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        _quietly(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
        _quietly(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-batch-sm-out-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1 specifically.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_sagemaker_queue(ctx, teardown_deadline) -> tuple[str, str]:
    batch = ctx.client("batch")

    # AWS Batch rejects SubmitServiceJob calls that set schedulingPriority/shareIdentifier
    # against a queue that has no scheduling policy attached, so attach a minimal
    # fair-share policy to the queue below.
    policy_name = ctx.unique_name("sim2real-svcschedpol-")
    policy_arn = batch.create_scheduling_policy(
        name=policy_name,
        fairsharePolicy={"computeReservation": 0, "shareDecaySeconds": 0, "shareDistribution": []},
    )["arn"]
    ctx.on_cleanup(lambda: _quietly(lambda: _retry_in_use(
        ctx, lambda: batch.delete_scheduling_policy(arn=policy_arn), teardown_deadline)))

    env_name = ctx.unique_name("sim2real-svcenv-")
    env_arn = batch.create_service_environment(
        serviceEnvironmentName=env_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "NUM_INSTANCES", "maxCapacity": 4}],
        state="ENABLED",
    )["serviceEnvironmentArn"]

    def _cleanup_env():
        _quietly(lambda: batch.update_service_environment(serviceEnvironment=env_arn, state="DISABLED"))
        _poll_until(
            lambda: batch.describe_service_environments(serviceEnvironments=[env_arn])["serviceEnvironments"][0]["status"],
            lambda s: s in ("VALID", "INVALID"),
            timeout_s=90,
        )
        _quietly(lambda: _retry_in_use(
            ctx, lambda: batch.delete_service_environment(serviceEnvironment=env_arn), teardown_deadline))

    ctx.on_cleanup(_cleanup_env)
    _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[env_arn])["serviceEnvironments"][0]["status"],
        lambda s: s in ("VALID", "INVALID"),
        timeout_s=90,
    )

    queue_name = ctx.unique_name("sim2real-svcq-")
    queue_arn = batch.create_job_queue(
        jobQueueName=queue_name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        state="ENABLED",
        schedulingPolicyArn=policy_arn,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": env_arn}],
    )["jobQueueArn"]

    def _cleanup_queue():
        _quietly(lambda: batch.update_job_queue(jobQueue=queue_arn, state="DISABLED"))
        _poll_until(
            lambda: batch.describe_job_queues(jobQueues=[queue_arn])["jobQueues"][0]["status"],
            lambda s: s in ("VALID", "INVALID"),
            timeout_s=90,
        )
        _quietly(lambda: _retry_in_use(ctx, lambda: batch.delete_job_queue(jobQueue=queue_arn), teardown_deadline))

    ctx.on_cleanup(_cleanup_queue)
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[queue_arn])["jobQueues"][0]["status"],
        lambda s: s in ("VALID", "INVALID"),
        timeout_s=90,
    )
    return queue_arn, env_arn


def _service_job_payload(ctx, job_name: str, role_arn: str, bucket: str, max_runtime: int = 60) -> str:
    payload = {
        "TrainingJobName": job_name,
        "RoleArn": role_arn,
        "AlgorithmSpecification": {
            "TrainingInputMode": "File",
            "TrainingImage": f"123456789012.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-training:2.0.0-cpu-py310",
            "ContainerEntrypoint": ["echo", "hello-world"],
        },
        "ResourceConfig": {"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 1},
        "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/output"},
        "StoppingCondition": {"MaxRuntimeInSeconds": max_runtime},
    }
    return json.dumps(payload)


#: The suite's cleanup budget; the retries of every teardown of one run share one deadline in it.
_CLEANUP_BUDGET_S = 900.0


def _retry_in_use(ctx, delete, teardown_deadline) -> None:
    """Run a Batch delete, retrying the "found existing ... relationship" refusal every 2 s to the
    run's cleanup deadline while a dependent finishes deleting; "does not exist" is gone."""
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _CLEANUP_BUDGET_S)
    while True:
        try:
            delete()
            return
        except ClientError as err:
            e = err.response["Error"]
            if e["Code"] == "ClientException" and "does not exist" in e.get("Message", ""):
                return
            in_use = e["Code"] == "ClientException" and "found existing" in e.get("Message", "")
            if not in_use or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
