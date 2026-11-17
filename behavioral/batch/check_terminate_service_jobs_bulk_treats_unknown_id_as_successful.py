"""terminate-service-jobs-bulk-treats-unknown-id-as-successful."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "terminate-service-jobs-bulk-treats-unknown-id-as-successful"
GROUP = "bulk-lifecycle"
SERVICES = ["batch", "iam", "s3"]

_MANAGED_TAGS = {"sim2real-check": CHECK}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TerminateServiceJobs reports a service job id it cannot find as successful rather
    than as an error, alongside the real jobs it actually terminates in the same call."""
    batch = ctx.client("batch")
    role_arn = _create_sagemaker_role(ctx)
    bucket = _create_output_bucket(ctx)
    queue_arn = _create_sagemaker_queue(ctx)

    job_ids = []
    for _ in range(2):
        name = ctx.unique_name("sim2real-batch-bulksj-")
        payload = _service_job_payload(ctx, name, role_arn, bucket)
        job_id = batch.submit_service_job(
            jobName=name,
            jobQueue=queue_arn,
            serviceJobType="SAGEMAKER_TRAINING",
            serviceRequestPayload=payload,
            schedulingPriority=1,
            shareIdentifier="default",
        )["jobId"]
        job_ids.append(job_id)

    for job_id in job_ids:
        before = _poll_until(
            lambda jid=job_id: batch.describe_service_job(jobId=jid),
            lambda job: job["status"] is not None,
            timeout_s=30,
        )
        assert before["status"] not in ("SUCCEEDED", "FAILED"), (
            f"expected freshly submitted job {job_id!r} to be non-terminal, got {before['status']!r}"
        )

    unknown_id = ctx.unique_name("sim2real-batch-unknown-sj-")
    reason = "sim2real-bulk-termination"
    requested = job_ids + [unknown_id]
    result = batch.terminate_service_jobs(jobs=requested, reason=reason)

    assert result["errors"] == [], (
        f"expected no per-job errors terminating {requested!r}, got {result['errors']!r}"
    )
    assert set(result["successful"]) == set(requested), (
        f"expected every requested id (real and unknown) reported successful, "
        f"got successful={sorted(result['successful'])!r} for requested={sorted(requested)!r}"
    )

    for job_id in job_ids:
        final = _poll_until(
            lambda jid=job_id: batch.describe_service_job(jobId=jid),
            lambda job: job["status"] == "FAILED",
            timeout_s=180,
        )
        assert final.get("isTerminated") is True, (
            f"job {job_id!r} reached FAILED but isTerminated was {final.get('isTerminated')!r}, expected True"
        )
        assert reason in (final.get("statusReason") or ""), (
            f"expected reason {reason!r} in statusReason for job {job_id!r}, got {final.get('statusReason')!r}"
        )


# ===== helpers =====

def _undo(fn, retry_s: float = 0.0) -> None:
    """Run a teardown step; "does not exist" means done. A ClientException for a
    resource still in use is retried every 2s for retry_s; anything else raises."""
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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_sagemaker_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-bulk-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        _undo(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
        _undo(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"],
        lambda policies: any(p["PolicyArn"] == policy_arn for p in policies),
        timeout_s=30,
        interval_s=2,
    )
    return role_arn


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-batch-bulk-out-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]},
    )

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_sagemaker_queue(ctx) -> str:
    batch = ctx.client("batch")

    # A SubmitServiceJob call that carries schedulingPriority/shareIdentifier requires the
    # target queue to have a scheduling policy attached; a minimal fairshare policy suffices.
    policy_name = ctx.unique_name("sim2real-batch-bulk-schedpol-")
    policy_arn = batch.create_scheduling_policy(
        name=policy_name,
        fairsharePolicy={"computeReservation": 0, "shareDecaySeconds": 0, "shareDistribution": []},
        tags=_MANAGED_TAGS,
    )["arn"]
    ctx.on_cleanup(lambda: _undo(lambda: batch.delete_scheduling_policy(arn=policy_arn), retry_s=90))

    env_name = ctx.unique_name("sim2real-batch-bulk-se-")
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

    queue_name = ctx.unique_name("sim2real-batch-bulk-sq-")
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
    return queue_arn


def _service_job_payload(ctx, job_name: str, role_arn: str, bucket: str, max_runtime: int = 300) -> str:
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
