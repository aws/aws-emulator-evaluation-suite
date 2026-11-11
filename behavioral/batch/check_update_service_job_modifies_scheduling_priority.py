"""update-service-job-modifies-scheduling-priority."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-service-job-modifies-scheduling-priority"
GROUP = "service-job"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateServiceJob changes schedulingPriority and the new value is immediately visible on
    DescribeServiceJob, leaving jobId, jobName and quotaShareName unchanged.
    """
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    batch = ctx.client("batch")
    role_arn = _create_sagemaker_role(ctx)
    bucket = _create_output_bucket(ctx)
    setup = _create_quota_share_job_queue(ctx, teardown_deadline)

    qs_name = ctx.unique_name("sim2real-batch-qs-")
    qs_arn = batch.create_quota_share(
        quotaShareName=qs_name,
        jobQueue=setup["queue_name"],
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 5}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        tags=_MANAGED_TAGS,
    )["quotaShareArn"]
    ctx.on_cleanup(lambda: _safe_delete_quota_share(batch, qs_arn))
    _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=qs_arn),
        lambda d: d["status"] == "VALID",
        timeout_s=180,
    )

    job_name = ctx.unique_name("sim2real-batch-sj-")
    payload = _service_payload(role_arn, bucket, job_name, ctx.region, max_runtime=1800)

    def _submit():
        return batch.submit_service_job(
            jobName=job_name,
            jobQueue=setup["queue_name"],
            serviceJobType="SAGEMAKER_TRAINING",
            serviceRequestPayload=payload,
            quotaShareName=qs_name,
            schedulingPriority=10,
            timeoutConfig={"attemptDurationSeconds": 3600},
            tags=_MANAGED_TAGS,
        )

    job_id = _call_with_role_propagation_retry(_submit)["jobId"]
    ctx.on_cleanup(lambda: _safe(lambda: batch.terminate_service_job(jobId=job_id, reason="sim2real-cleanup")))

    before = batch.describe_service_job(jobId=job_id)
    assert before["schedulingPriority"] == 10, f"expected initial schedulingPriority=10, got {before['schedulingPriority']!r}"
    assert before["quotaShareName"] == qs_name, f"expected quotaShareName={qs_name!r}, got {before['quotaShareName']!r}"

    batch.update_service_job(jobId=job_id, schedulingPriority=50)

    after = batch.describe_service_job(jobId=job_id)
    assert after["schedulingPriority"] == 50, f"expected schedulingPriority=50 after update, got {after['schedulingPriority']!r}"
    # Identity/association fields are untouched by the priority-only update.
    assert after["jobId"] == job_id, f"expected jobId={job_id!r} unchanged, got {after['jobId']!r}"
    assert after["jobName"] == job_name, f"expected jobName={job_name!r} unchanged, got {after['jobName']!r}"
    assert after["quotaShareName"] == qs_name, f"expected quotaShareName={qs_name!r} unchanged, got {after['quotaShareName']!r}"


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


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
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


def _call_with_role_propagation_retry(fn, *, timeout_s=90.0, interval_s=5.0):
    """Retry a call that needs the freshly-created role to be assumable, bounded by a deadline.

    IAM trust-policy propagation to Batch/SageMaker has no independent readiness signal --
    this retries the actual dependent call instead of sleeping blind.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code in ("ClientException", "ServerException") and "sts:AssumeRole" in message:
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    assert last_err is not None
    raise last_err


def _create_output_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-batch-smout-")
    # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1 (it is the API default),
    # so this is comparing against ctx.region, not pinning the check to a hardcoded region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]},
    )

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


def _create_quota_share_job_queue(ctx, teardown_deadline):
    batch = ctx.client("batch")
    policy_name = ctx.unique_name("sim2real-batch-qsp-")
    policy_arn = batch.create_scheduling_policy(
        name=policy_name,
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags=_MANAGED_TAGS,
    )["arn"]
    ctx.on_cleanup(lambda: _safe(lambda: _retry_in_use(
        ctx, lambda: batch.delete_scheduling_policy(arn=policy_arn), teardown_deadline)))

    env_name = ctx.unique_name("sim2real-batch-senv-")
    env_arn = batch.create_service_environment(
        serviceEnvironmentName=env_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 10}],
        tags=_MANAGED_TAGS,
    )["serviceEnvironmentArn"]

    def _cleanup_env():
        try:
            batch.update_service_environment(serviceEnvironment=env_arn, state="DISABLED")
            for _ in range(40):
                d = batch.describe_service_environments(serviceEnvironments=[env_arn])
                if d["serviceEnvironments"][0]["status"] in ("VALID", "INVALID"):
                    break
                time.sleep(3)
            _retry_in_use(ctx, lambda: batch.delete_service_environment(serviceEnvironment=env_arn), teardown_deadline)
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

    queue_name = ctx.unique_name("sim2real-batch-qsq-")
    queue_arn = batch.create_job_queue(
        jobQueueName=queue_name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        serviceEnvironmentOrder=[{"serviceEnvironment": env_arn, "order": 1}],
        schedulingPolicyArn=policy_arn,
        tags=_MANAGED_TAGS,
    )["jobQueueArn"]

    def _cleanup_queue():
        try:
            batch.update_job_queue(jobQueue=queue_arn, state="DISABLED")
            for _ in range(40):
                d = batch.describe_job_queues(jobQueues=[queue_arn])
                if d["jobQueues"][0]["status"] in ("VALID", "INVALID"):
                    break
                time.sleep(3)
            _retry_in_use(ctx, lambda: batch.delete_job_queue(jobQueue=queue_arn), teardown_deadline)
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
    return {"policy_arn": policy_arn, "env_arn": env_arn, "queue_name": queue_name, "queue_arn": queue_arn}


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
