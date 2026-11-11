"""terminate-service-job-transitions-to-failed."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "terminate-service-job-transitions-to-failed"
GROUP = "service-job"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """TerminateServiceJob on a non-terminal service job moves it to FAILED, with the
    supplied termination reason surfaced verbatim as statusReason on DescribeServiceJob,
    and isTerminated flips to True."""
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
    job_id = _submit_with_role_retry(
        ctx,
        batch,
        jobName=job_name,
        jobQueue=queue["queue_name"],
        serviceJobType="SAGEMAKER_TRAINING",
        serviceRequestPayload=payload,
        quotaShareName=qs_name,
        # Real AWS Batch rejects SAGEMAKER_TRAINING service jobs submitted to a job
        # queue backed by a quota-management scheduling policy with ClientException
        # ("Job without schedulingPriority cannot be submitted to a job queue with a
        # ... scheduling policy") unless schedulingPriority is supplied.
        schedulingPriority=10,
        timeoutConfig={"attemptDurationSeconds": 3600},
    )["jobId"]

    before = batch.describe_service_job(jobId=job_id)
    assert before["status"] in (
        "SUBMITTED",
        "PENDING",
        "RUNNABLE",
        "SCHEDULED",
        "STARTING",
        "RUNNING",
    ), f"expected a non-terminal status right after submit, got {before['status']!r}"
    # Real DescribeServiceJob omits the "isTerminated" field entirely while a job is
    # not terminated (it is only populated once the job actually terminates), so a
    # missing key is equivalent to False rather than a defect.
    assert before.get("isTerminated", False) is False, f"expected isTerminated=False, got {before.get('isTerminated')!r}"

    reason = f"sim2real-terminate-reason-{ctx.unique_name('')}"
    batch.terminate_service_job(jobId=job_id, reason=reason)

    # Poll until both the terminal status and the isTerminated flag have landed --
    # they can be reported by DescribeServiceJob in slightly separate updates.
    after = _poll_until(
        lambda: batch.describe_service_job(jobId=job_id),
        lambda d: d["status"] == "FAILED" and d.get("isTerminated") is True,
        timeout_s=120,
    )
    assert after["isTerminated"] is True, f"expected isTerminated=True after terminate, got {after.get('isTerminated')!r}"
    assert reason in (after.get("statusReason") or ""), (
        f"expected statusReason to contain {reason!r}, got {after.get('statusReason')!r}"
    )


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)))
    return role_arn


def _submit_with_role_retry(ctx, batch, **kwargs):
    """SubmitServiceJob, retried every 2 s while Batch refuses the just-created role (IAM is
    eventually consistent), for up to 60 s capped by the run's remaining time."""
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else max(1.0, min(60.0, left - 5.0)))
    while True:
        try:
            return batch.submit_service_job(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if (
                err["Code"] != "ClientException"
                or "role" not in err.get("Message", "").lower()
                or time.monotonic() >= deadline
            ):
                raise
        time.sleep(2)


def _create_output_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-batch-smout-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

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
                "TrainingImage": f"123456789012.dkr.ecr.{region}.amazonaws.com/pytorch-training:2.1.0-cpu-py310",
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
    )["arn"]
    ctx.on_cleanup(lambda: _safe(lambda: batch.delete_scheduling_policy(arn=policy_arn)))

    env_name = ctx.unique_name("sim2real-batch-senv-")
    env_arn = batch.create_service_environment(
        serviceEnvironmentName=env_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 5}],
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
            # DeleteJobQueue is asynchronous; the service-environment and scheduling-policy
            # deletes that run next (LIFO) are refused while the queue still references them.
            deadline = time.monotonic() + 180.0
            while batch.describe_job_queues(jobQueues=[queue_arn])["jobQueues"]:
                if time.monotonic() > deadline:
                    raise AssertionError("job queue still present 180s after its delete")
                time.sleep(2)
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
    # DeleteQuotaShare is asynchronous; the job queue's delete (next, LIFO) is refused with
    # "found existing QuotaShare relationship" until the share is gone.
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        try:
            batch.describe_quota_share(quotaShareArn=arn)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                return
            raise
        time.sleep(2)
    raise AssertionError("quota share still present 120s after DeleteQuotaShare")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
