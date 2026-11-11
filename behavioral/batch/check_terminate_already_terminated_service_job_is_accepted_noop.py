"""terminate-already-terminated-service-job-is-accepted-noop."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "terminate-already-terminated-service-job-is-accepted-noop"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A second TerminateServiceJob on a service job already FAILED with isTerminated true succeeds,
    and the job keeps status FAILED and the first call's statusReason: the redundant call is a
    no-op."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    batch = ctx.client("batch")

    role_arn = _create_sagemaker_execution_role(ctx)
    bucket = _create_output_bucket(ctx)
    jq_name, _se_name = _create_sagemaker_queue(ctx, teardown_deadline)

    job_name = ctx.unique_name("sim2real-batch-sj-")
    payload = _service_job_payload(ctx, job_name, role_arn, bucket, max_runtime=300)
    # The SageMaker execution role was just created; IAM propagation can lag long enough
    # for SubmitServiceJob to reject it before it is assumable, so retry within a bounded window.
    submitted = _call_with_role_propagation_retry(
        lambda: batch.submit_service_job(
            jobName=job_name,
            jobQueue=jq_name,
            serviceJobType="SAGEMAKER_TRAINING",
            serviceRequestPayload=payload,
            schedulingPriority=1,
            # The queue has a fairshare scheduling policy attached, and real AWS Batch
            # requires every job submitted to such a queue to carry a shareIdentifier.
            shareIdentifier="default",
        )
    )
    job_id = submitted["jobId"]
    assert job_id

    # First termination must succeed while the job is still non-terminal.
    batch.terminate_service_job(jobId=job_id, reason="sim2real-first-terminate")

    job = _poll_until(
        lambda: batch.describe_service_job(jobId=job_id),
        lambda j: j["status"] in ("FAILED", "SUCCEEDED"),
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert job["status"] == "FAILED", f"expected terminated job to be FAILED, got {job['status']!r}"
    assert job["isTerminated"] is True

    # A second termination on an already-terminal job is accepted by the API as a
    # no-op (real AWS Batch does not raise for a redundant terminate call here).
    code = None
    try:
        batch.terminate_service_job(jobId=job_id, reason="sim2real-second-terminate")
    except ClientError as err:
        code = err.response["Error"]["Code"]
    assert code is None, (
        f"expected the redundant terminate call on an already-terminal service job "
        f"to be accepted as a no-op, but it raised {code!r}"
    )

    # The redundant second call must not have mutated the job's recorded state.
    job_after = batch.describe_service_job(jobId=job_id)
    assert job_after["status"] == "FAILED"
    assert job_after["statusReason"] == "sim2real-first-terminate", (
        f"redundant terminate call must not overwrite statusReason, got {job_after['statusReason']!r}"
    )


def _call_with_role_propagation_retry(fn: Callable[[], Any], *, timeout_s: float = 90.0, interval_s: float = 5.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException", "ClientException"):
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    assert last_err is not None
    raise last_err


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 120.0, interval_s: float = 3.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-batch-sm-out-").lower().replace("_", "-")
    # S3's CreateBucket rejects an explicit LocationConstraint of "us-east-1" (it must be
    # omitted for that region specifically); the bucket still lands in ctx.region either way.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup() -> None:
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
        tags={"sim2real:check": CHECK},
    )["arn"]

    def _cleanup_policy() -> None:
        _retry_in_use(ctx, lambda: batch.delete_scheduling_policy(arn=policy_arn), teardown_deadline)

    ctx.on_cleanup(_cleanup_policy)

    env_name = ctx.unique_name("sim2real-svcenv-")
    env_arn = batch.create_service_environment(
        serviceEnvironmentName=env_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "NUM_INSTANCES", "maxCapacity": 4}],
        state="ENABLED",
        tags={"sim2real:check": CHECK},
    )["serviceEnvironmentArn"]

    def _cleanup_env() -> None:
        try:
            batch.update_service_environment(serviceEnvironment=env_arn, state="DISABLED")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
        try:
            _poll_until(
                lambda: batch.describe_service_environments(serviceEnvironments=[env_arn])["serviceEnvironments"][0]["status"],
                lambda s: s in ("VALID", "INVALID"),
                timeout_s=90.0,
                interval_s=3.0,
            )
        except AssertionError:
            pass
        _retry_in_use(ctx, lambda: batch.delete_service_environment(serviceEnvironment=env_arn), teardown_deadline)

    ctx.on_cleanup(_cleanup_env)
    _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[env_arn])["serviceEnvironments"][0]["status"],
        lambda s: s in ("VALID", "INVALID"),
        timeout_s=90.0,
        interval_s=3.0,
    )

    queue_name = ctx.unique_name("sim2real-svcq-")
    queue_arn = batch.create_job_queue(
        jobQueueName=queue_name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        state="ENABLED",
        schedulingPolicyArn=policy_arn,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": env_arn}],
        tags={"sim2real:check": CHECK},
    )["jobQueueArn"]

    def _cleanup_queue() -> None:
        try:
            batch.update_job_queue(jobQueue=queue_arn, state="DISABLED")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
        try:
            _poll_until(
                lambda: batch.describe_job_queues(jobQueues=[queue_arn])["jobQueues"][0]["status"],
                lambda s: s in ("VALID", "INVALID"),
                timeout_s=90.0,
                interval_s=3.0,
            )
        except AssertionError:
            pass
        _retry_in_use(ctx, lambda: batch.delete_job_queue(jobQueue=queue_arn), teardown_deadline)

    ctx.on_cleanup(_cleanup_queue)
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[queue_arn])["jobQueues"][0]["status"],
        lambda s: s in ("VALID", "INVALID"),
        timeout_s=90.0,
        interval_s=3.0,
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
