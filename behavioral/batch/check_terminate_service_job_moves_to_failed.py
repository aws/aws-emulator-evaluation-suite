"""terminate-service-job-moves-to-failed."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "terminate-service-job-moves-to-failed"
GROUP = "state-machine"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK}


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TerminateServiceJob on a running/non-terminal service job forces its
    DescribeServiceJob status to FAILED with isTerminated=True and the supplied reason
    recorded in statusReason."""
    batch = ctx.client("batch")
    role_arn = _create_sagemaker_execution_role(ctx)
    bucket = _create_output_bucket(ctx)
    queue_arn, _env_arn = _create_sagemaker_queue(ctx)

    job_name = ctx.unique_name("sim2real-svcjob-")
    payload = _service_job_payload(ctx, job_name, role_arn, bucket, max_runtime=300)
    job_id = batch.submit_service_job(
        jobName=job_name,
        jobQueue=queue_arn,
        serviceJobType="SAGEMAKER_TRAINING",
        serviceRequestPayload=payload,
        schedulingPriority=1,
        # The queue has a fairshare scheduling policy attached, and real AWS Batch
        # requires every job submitted to such a queue to carry a shareIdentifier.
        shareIdentifier="default",
    )["jobId"]

    before = batch.describe_service_job(jobId=job_id)
    assert before["status"] not in ("SUCCEEDED", "FAILED"), (
        f"expected a freshly submitted service job to be non-terminal, got status={before['status']!r}"
    )
    # Real AWS Batch omits the isTerminated boolean from DescribeServiceJob when it is
    # False (rather than always including it), so default to False when absent.
    assert before.get("isTerminated", False) is False, (
        f"expected isTerminated False/absent before termination, got {before.get('isTerminated')!r}"
    )

    reason = "sim2real-forced-termination"
    batch.terminate_service_job(jobId=job_id, reason=reason)

    final = _poll_until(
        lambda: batch.describe_service_job(jobId=job_id),
        lambda d: d["status"] == "FAILED",
        timeout_s=180,
    )
    assert final.get("isTerminated") is True, (
        f"expected isTerminated True once status reached FAILED, got {final.get('isTerminated')!r}"
    )
    assert reason in (final.get("statusReason") or ""), (
        f"expected termination reason {reason!r} to appear in statusReason, got {final.get('statusReason')!r}"
    )

    # Terminating again on an already-terminal job is a safe no-op (call still succeeds)
    # and must not overwrite the state recorded by the first call.
    batch.terminate_service_job(jobId=job_id, reason="second-call")
    still = batch.describe_service_job(jobId=job_id)
    assert still["status"] == "FAILED", (
        f"expected status to remain FAILED after a redundant terminate call, got {still['status']!r}"
    )
    assert still.get("statusReason") == final.get("statusReason"), (
        f"expected a redundant terminate call not to overwrite statusReason, "
        f"before={final.get('statusReason')!r} after={still.get('statusReason')!r}"
    )


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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_tags_kv()
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        _undo(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
        _undo(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    # Wait for IAM's control plane to report the attachment before SageMaker is asked
    # to assume the role, instead of a blind sleep for propagation.
    _poll_until(
        lambda: iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"],
        lambda policies: any(p["PolicyArn"] == policy_arn for p in policies),
        timeout_s=30,
        interval_s=2,
    )
    return role_arn


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-batch-sm-out-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_kv()})

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
        tags=_MANAGED_TAGS,
    )["arn"]
    ctx.on_cleanup(lambda: _undo(lambda: batch.delete_scheduling_policy(arn=policy_arn), retry_s=90))

    env_name = ctx.unique_name("sim2real-svcenv-")
    env_arn = batch.create_service_environment(
        serviceEnvironmentName=env_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "NUM_INSTANCES", "maxCapacity": 4}],
        state="ENABLED",
        tags=_MANAGED_TAGS,
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
        tags=_MANAGED_TAGS,
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
            "TrainingImage": f"123456789012.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-training:2.0.0-cpu-py310",
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
