"""update-service-job-modifies-desired-state."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "update-service-job-modifies-desired-state"
GROUP = "state-machine"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c3", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateServiceJob mutates the service job's schedulingPriority and the change is
    immediately visible via DescribeServiceJob."""
    batch = ctx.client("batch")
    role_arn = _create_sagemaker_execution_role(ctx)
    bucket = _create_output_bucket(ctx)
    queue_arn, _env_arn = _create_sagemaker_queue(ctx)

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
        tags={"sim2real:managed": "true"},
    )["jobId"]
    ctx.on_cleanup(lambda: _undo(lambda: batch.terminate_service_job(jobId=job_id, reason="test-cleanup")))

    before = batch.describe_service_job(jobId=job_id)
    assert before["schedulingPriority"] == 1, f"expected initial schedulingPriority=1, got {before['schedulingPriority']!r}"

    update_resp = batch.update_service_job(jobId=job_id, schedulingPriority=777)
    assert update_resp["jobId"] == job_id, f"expected UpdateServiceJob to echo jobId={job_id!r}, got {update_resp['jobId']!r}"
    assert update_resp["jobName"] == job_name, (
        f"expected UpdateServiceJob to echo jobName={job_name!r}, got {update_resp['jobName']!r}"
    )

    after = batch.describe_service_job(jobId=job_id)
    assert after["schedulingPriority"] == 777, (
        f"expected schedulingPriority=777 after UpdateServiceJob, got {after['schedulingPriority']!r}"
    )
    # The mutation was scoped to schedulingPriority only; identity fields are unchanged.
    assert after["jobId"] == job_id, f"expected jobId to remain {job_id!r}, got {after['jobId']!r}"
    assert after["jobName"] == job_name, f"expected jobName to remain {job_name!r}, got {after['jobName']!r}"
    assert after["jobQueue"] == queue_arn, f"expected jobQueue to remain {queue_arn!r}, got {after['jobQueue']!r}"


# ===== helpers =====

def _undo(fn: Callable[[], Any], retry_s: float = 0.0) -> None:
    """Run a teardown step; a resource that does not exist is done. Batch's ClientException for a
    resource still in use is retried every 2 s for retry_s; anything else raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + retry_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            e = err.response["Error"]
            if e["Code"] == "NoSuchEntity" or (
                e["Code"] == "ClientException" and "does not exist" in e.get("Message", "")
            ):
                return
            if e["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        _undo(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
        _undo(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    return role_arn


def _submit_service_job_with_retry(batch, *, timeout_s: float = 60.0, interval_s: float = 5.0, **kwargs):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return batch.submit_service_job(**kwargs)
        except ClientError as exc:  # IAM role/policy propagation before SageMaker can assume it
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"submit_service_job did not succeed within {timeout_s}s; last_err={last_err!r}")


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-batch-sm-out-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
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


def _create_sagemaker_queue(ctx) -> tuple[str, str]:
    batch = ctx.client("batch")

    # AWS Batch rejects SubmitServiceJob calls that set schedulingPriority/shareIdentifier
    # against a queue that has no scheduling policy attached, so attach a minimal
    # fair-share policy to the queue below.
    policy_name = ctx.unique_name("sim2real-svcschedpol-")
    policy_arn = batch.create_scheduling_policy(
        name=policy_name,
        fairsharePolicy={"computeReservation": 0, "shareDecaySeconds": 0, "shareDistribution": []},
        tags={"sim2real:managed": "true"},
    )["arn"]
    ctx.on_cleanup(lambda: _undo(lambda: batch.delete_scheduling_policy(arn=policy_arn), retry_s=90))

    env_name = ctx.unique_name("sim2real-svcenv-")
    env_arn = batch.create_service_environment(
        serviceEnvironmentName=env_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "NUM_INSTANCES", "maxCapacity": 4}],
        state="ENABLED",
        tags={"sim2real:managed": "true"},
    )["serviceEnvironmentArn"]

    def _cleanup_env():
        _undo(lambda: batch.update_service_environment(serviceEnvironment=env_arn, state="DISABLED"))
        _poll_until(
            lambda: batch.describe_service_environments(serviceEnvironments=[env_arn])["serviceEnvironments"][0]["status"],
            lambda s: s in ("VALID", "INVALID"),
            timeout_s=90,
        )
        _undo(lambda: batch.delete_service_environment(serviceEnvironment=env_arn), retry_s=90)

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
        tags={"sim2real:managed": "true"},
    )["jobQueueArn"]

    def _cleanup_queue():
        _undo(lambda: batch.update_job_queue(jobQueue=queue_arn, state="DISABLED"))
        _poll_until(
            lambda: batch.describe_job_queues(jobQueues=[queue_arn])["jobQueues"][0]["status"],
            lambda s: s in ("VALID", "INVALID"),
            timeout_s=90,
        )
        _undo(lambda: batch.delete_job_queue(jobQueue=queue_arn), retry_s=90)

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
            "TrainingImage": f"763104351884.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-training:2.0.0-cpu-py310",
            "ContainerEntrypoint": ["echo", "hello-world"],
        },
        "ResourceConfig": {"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 1},
        "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/output"},
        "StoppingCondition": {"MaxRuntimeInSeconds": max_runtime},
    }
    return json.dumps(payload)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
