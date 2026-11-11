"""update-service-job-on-terminal-job-fails."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-service-job-on-terminal-job-fails"
GROUP = "overly-permissive"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateServiceJob applies on an active job but fails with ClientException once it is FAILED.

    The rejected update leaves schedulingPriority and the FAILED status unchanged."""
    batch = ctx.client("batch")
    role_arn = _create_sagemaker_role(ctx)
    bucket = _create_output_bucket(ctx)
    queue = _create_service_job_queue(ctx)
    # Real AWS Batch requires SAGEMAKER_TRAINING service jobs submitted to a job queue
    # bound to a quota-management scheduling policy to carry a quotaShareName; without
    # it, SubmitServiceJob is rejected outright with ClientException before a job is
    # ever created.
    qs_name = _create_quota_share(ctx, batch, queue["queue_name"])

    job_name = ctx.unique_name("sim2real-batch-sj-")
    payload = _service_payload(role_arn, bucket, job_name, ctx.region, max_runtime=1800)
    job_id = _submit_service_job(
        batch, job_name, queue["queue_name"], payload, qs_name, scheduling_priority=5
    )

    # Positive control: UpdateServiceJob against the still-active job is accepted and its
    # effect is visible on an independent read. Without this leg, "rejects the update on a
    # terminal job" would be indistinguishable from "rejects the update unconditionally".
    batch.update_service_job(jobId=job_id, schedulingPriority=7)
    active = batch.describe_service_job(jobId=job_id)
    assert active["schedulingPriority"] == 7, "positive control: update on an active job must apply"
    assert active["status"] not in ("FAILED", "SUCCEEDED"), (
        f"control job unexpectedly already terminal: {active['status']!r}"
    )

    batch.terminate_service_job(jobId=job_id, reason="sim2real-force-terminal-for-negative-test")
    terminal = _poll_until(
        lambda: batch.describe_service_job(jobId=job_id),
        lambda d: d["status"] == "FAILED",
        timeout_s=120,
    )
    assert terminal["isTerminated"] is True, f"expected isTerminated after FAILED, got {terminal!r}"
    assert terminal["schedulingPriority"] == 7, f"expected priority carried over from the positive control, got {terminal['schedulingPriority']!r}"

    error = _error(lambda: batch.update_service_job(jobId=job_id, schedulingPriority=99))
    code, message = error.get("Code"), error.get("Message")
    assert code == "ClientException", f"expected ClientException updating a terminal service job, got {code!r}"
    assert message == "UpdateServiceJob cannot be called on a service job which is completed.", f"expected the exact terminal-job update refusal message, got {message!r}"

    unchanged = batch.describe_service_job(jobId=job_id)
    assert unchanged["schedulingPriority"] == 7, "rejected update must not have mutated schedulingPriority"
    assert unchanged["status"] == "FAILED", f"expected status to remain FAILED, got {unchanged['status']!r}"


_MANAGED_TAGS = {
    "sim2real:managed": "true",
    "sim2real:prefix": "sim2real-batch",
    "sim2real": CHECK,
}


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _submit_service_job(batch, job_name, queue_name, payload, qs_name, *, scheduling_priority, timeout_s=90.0):
    from botocore.exceptions import ClientError

    # A freshly created IAM role can take a few seconds to propagate before Batch will
    # accept it on a SubmitServiceJob call; retry ClientException submissions within a
    # bounded window.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return batch.submit_service_job(
                jobName=job_name,
                jobQueue=queue_name,
                serviceJobType="SAGEMAKER_TRAINING",
                serviceRequestPayload=payload,
                quotaShareName=qs_name,
                schedulingPriority=scheduling_priority,
                timeoutConfig={"attemptDurationSeconds": 3600},
                tags=dict(_MANAGED_TAGS),
            )["jobId"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClientException":
                raise
            last_exc = exc
            time.sleep(5)
    raise last_exc


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_quota_share(ctx, batch, queue_name, *, max_capacity=5):
    qs_name = ctx.unique_name("sim2real-batch-qs-")
    qs_arn = batch.create_quota_share(
        quotaShareName=qs_name,
        jobQueue=queue_name,
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": max_capacity}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        tags=dict(_MANAGED_TAGS),
    )["quotaShareArn"]
    ctx.on_cleanup(lambda: _safe_delete_quota_share(batch, qs_arn))
    _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=qs_arn),
        lambda d: d["status"] == "VALID",
        timeout_s=180,
    )
    return qs_name


def _safe_delete_quota_share(batch, arn):
    try:
        batch.update_quota_share(quotaShareArn=arn, state="DISABLED")
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ClientException"
            and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
        ):
            raise
    for _ in range(20):
        try:
            desc = batch.describe_quota_share(quotaShareArn=arn)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
            return
        if desc.get("status") == "VALID":
            break
        time.sleep(3)
    batch.delete_quota_share(quotaShareArn=arn)


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_tags_kv()
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)))
    for _ in range(15):
        try:
            iam.get_role(RoleName=role_name)
            break
        except Exception:
            time.sleep(2)
    return role_arn


def _create_output_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-batch-smout-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_kv()})

    def _cleanup_bucket():
        try:
            resp = s3.list_objects_v2(Bucket=bucket)
            for obj in resp.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup_bucket)
    return bucket


def _service_payload(role_arn, bucket, training_job_name, region, max_runtime=180):
    return json.dumps(
        {
            "TrainingJobName": training_job_name,
            "RoleArn": role_arn,
            "AlgorithmSpecification": {
                "TrainingInputMode": "File",
                "TrainingImage": f"763104351884.dkr.ecr.{region}.amazonaws.com/pytorch-training:2.1.0-cpu-py310",
                "ContainerEntrypoint": ["sleep", str(max_runtime + 60)],
            },
            "ResourceConfig": {"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 1},
            "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/output"},
            "StoppingCondition": {"MaxRuntimeInSeconds": max_runtime},
        }
    )


def _create_service_job_queue(ctx):
    batch = ctx.client("batch")

    # A SAGEMAKER_TRAINING service environment declares capacityLimits, which makes it
    # "Quota Management compatible" -- real AWS Batch then requires the job queue that
    # references it to carry a schedulingPolicyArn (a quota-management scheduling
    # policy); CreateJobQueue is rejected with ClientException otherwise.
    policy_name = ctx.unique_name("sim2real-batch-qsp-")
    policy_arn = batch.create_scheduling_policy(
        name=policy_name,
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags=dict(_MANAGED_TAGS),
    )["arn"]
    ctx.on_cleanup(lambda: _safe(lambda: batch.delete_scheduling_policy(arn=policy_arn)))

    env_name = ctx.unique_name("sim2real-batch-senv-")
    env_arn = batch.create_service_environment(
        serviceEnvironmentName=env_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 5}],
        tags=dict(_MANAGED_TAGS),
    )["serviceEnvironmentArn"]

    def _cleanup_env():
        try:
            batch.update_service_environment(serviceEnvironment=env_arn, state="DISABLED")
            for _ in range(40):
                d = batch.describe_service_environments(serviceEnvironments=[env_arn])
                if d["serviceEnvironments"][0]["status"] in ("VALID", "INVALID"):
                    break
                time.sleep(3)
            batch.delete_service_environment(serviceEnvironment=env_arn)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise

    ctx.on_cleanup(_cleanup_env)
    _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[env_arn])["serviceEnvironments"][0],
        lambda e: e["status"] == "VALID",
        timeout_s=120,
    )

    queue_name = ctx.unique_name("sim2real-batch-sjq-")
    queue_arn = batch.create_job_queue(
        jobQueueName=queue_name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        serviceEnvironmentOrder=[{"serviceEnvironment": env_arn, "order": 1}],
        schedulingPolicyArn=policy_arn,
        tags=dict(_MANAGED_TAGS),
    )["jobQueueArn"]

    def _cleanup_queue():
        try:
            batch.update_job_queue(jobQueue=queue_arn, state="DISABLED")
            for _ in range(40):
                d = batch.describe_job_queues(jobQueues=[queue_arn])
                if d["jobQueues"][0]["status"] in ("VALID", "INVALID"):
                    break
                time.sleep(3)
            batch.delete_job_queue(jobQueue=queue_arn)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise

    ctx.on_cleanup(_cleanup_queue)
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[queue_arn])["jobQueues"][0],
        lambda q: q["status"] == "VALID",
        timeout_s=120,
    )
    return {"env_arn": env_arn, "queue_name": queue_name, "queue_arn": queue_arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
