"""quota-share-enforced-server-side-on-job-scheduling."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "quota-share-enforced-server-side-on-job-scheduling"
GROUP = "server-side"
SERVICES = ["batch"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch-qsp"}


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Under a quota share with maxCapacity=1, one of two single-instance service jobs leaves RUNNABLE
    while the other is held at RUNNABLE; once the first is terminated, the held job advances past
    RUNNABLE: the share's capacity gates admission server-side."""

    batch = ctx.client("batch")

    role_arn = _create_sagemaker_role(ctx)
    bucket = _create_output_bucket(ctx)

    policy_name = ctx.unique_name("sim2real-batch-qsp-")
    try:
        # FIFO is the only value the QuotaShareIdleResourceAssignmentStrategy enum defines
        # (com.amazonaws.batch#QuotaShareIdleResourceAssignmentStrategy in the Smithy model) --
        # any other value is a malformed request, not an account/region restriction.
        policy_arn = batch.create_scheduling_policy(
            name=policy_name,
            quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
            tags=_TAGS,
        )["arn"]
    except ClientError as e:
        raise AssertionError(f"unable to create a quotaSharePolicy scheduling policy: {e}")
    ctx.on_cleanup(lambda: _try_delete_scheduling_policy(ctx, policy_arn))

    se_name = ctx.unique_name("sim2real-batch-se-")
    try:
        se_arn = batch.create_service_environment(
            serviceEnvironmentName=se_name,
            serviceEnvironmentType="SAGEMAKER_TRAINING",
            state="ENABLED",
            capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 4}],
            tags=_TAGS,
        )["serviceEnvironmentArn"]
    except ClientError as e:
        raise AssertionError(f"unable to create a SAGEMAKER_TRAINING service environment: {e}")
    ctx.on_cleanup(lambda: _drain_and_delete_se(ctx, se_name))
    _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[se_name])["serviceEnvironments"][0],
        lambda se: se["status"] in ("VALID", "INVALID"),
        timeout_s=90,
        interval_s=4,
    )

    queue_name = ctx.unique_name("sim2real-batch-jq-")
    try:
        batch.create_job_queue(
            jobQueueName=queue_name,
            state="ENABLED",
            priority=1,
            jobQueueType="SAGEMAKER_TRAINING",
            schedulingPolicyArn=policy_arn,
            serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": se_arn}],
            tags=_TAGS,
        )["jobQueueArn"]
    except ClientError as e:
        raise AssertionError(f"unable to create a SAGEMAKER_TRAINING job queue: {e}")
    ctx.on_cleanup(lambda: _drain_and_delete_jq(ctx, queue_name))
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[queue_name])["jobQueues"][0],
        lambda jq: jq["status"] in ("VALID", "INVALID"),
        timeout_s=90,
        interval_s=4,
    )

    quota_share_name = ctx.unique_name("sim2real-batch-qs-")
    try:
        qs_arn = batch.create_quota_share(
            quotaShareName=quota_share_name,
            jobQueue=queue_name,
            state="ENABLED",
            capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 1}],
            resourceSharingConfiguration={"strategy": "RESERVE"},
            preemptionConfiguration={"inSharePreemption": "DISABLED"},
            tags=_TAGS,
        )["quotaShareArn"]
    except ClientError as e:
        raise AssertionError(f"unable to create a quota share: {e}")
    ctx.on_cleanup(lambda: _try_delete_quota_share(ctx, qs_arn))
    _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=qs_arn),
        lambda qs: qs["status"] in ("VALID", "INVALID"),
        timeout_s=90,
        interval_s=4,
    )

    # An AWS Deep Learning Container image, hosted in AWS's own ECR account. SageMaker rejects
    # any other registry (including public.ecr.aws) as "a private Docker registry" unless the
    # request also carries a TrainingImageConfig with TrainingRepositoryAccessMode=Vpc.
    training_image = f"763104351884.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-training:2.0.0-cpu-py310"

    def _payload(job_name: str) -> str:
        return json.dumps(
            {
                "TrainingJobName": job_name,
                "AlgorithmSpecification": {
                    "TrainingImage": training_image,
                    "TrainingInputMode": "File",
                    # The job holds its capacity until this check terminates it, so the
                    # contention window is the check's own, not a race against a no-op job.
                    "ContainerEntrypoint": ["sleep", "900"],
                },
                "RoleArn": role_arn,
                "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/output/"},
                "ResourceConfig": {"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
                "StoppingCondition": {"MaxRuntimeInSeconds": 900},
            }
        )

    job_ids: list[str] = []
    try:
        job1 = _submit_with_role_propagation_wait(
            lambda: batch.submit_service_job(
                jobName=ctx.unique_name("sim2real-batch-sj1-"),
                jobQueue=queue_name,
                serviceJobType="SAGEMAKER_TRAINING",
                # A job queue backed by a quota share scheduling policy rejects a submission
                # with no schedulingPriority (SubmitServiceJobRequest$schedulingPriority, 0-9999).
                schedulingPriority=1,
                quotaShareName=quota_share_name,
                serviceRequestPayload=_payload("sim2real-tj-" + uuid.uuid4().hex[:8]),
            )
        )["jobId"]
        job_ids.append(job1)
        job2 = _submit_with_role_propagation_wait(
            lambda: batch.submit_service_job(
                jobName=ctx.unique_name("sim2real-batch-sj2-"),
                jobQueue=queue_name,
                serviceJobType="SAGEMAKER_TRAINING",
                schedulingPriority=1,
                quotaShareName=quota_share_name,
                serviceRequestPayload=_payload("sim2real-tj-" + uuid.uuid4().hex[:8]),
            )
        )["jobId"]
        job_ids.append(job2)
    except ClientError as e:
        raise AssertionError(f"SubmitServiceJob rejected the SageMaker training payload in this environment: {e}")
    ctx.on_cleanup(lambda: _try_terminate_service_jobs(ctx, job_ids))

    def _statuses() -> dict[str, str]:
        return {
            job1: batch.describe_service_job(jobId=job1)["status"],
            job2: batch.describe_service_job(jobId=job2)["status"],
        }

    # The quota share's capacity is claimed when a job leaves RUNNABLE for SCHEDULED (RUNNABLE is
    # the held state, not PENDING or SUBMITTED) and held through STARTING/RUNNING/terminal.
    capacity_consuming_states = {"SCHEDULED", "STARTING", "RUNNING", "SUCCEEDED", "FAILED"}
    # job1 sleeps far longer than this check waits, so while it is in one of these non-terminal
    # states it is still holding the share's only unit; that is the window job2 is graded in.
    holding_states = {"SCHEDULED", "STARTING", "RUNNING"}

    holding = _poll_until(
        _statuses,
        lambda s: s[job1] in holding_states,
        timeout_s=120,
        interval_s=5,
    )
    assert holding[job1] in holding_states, (
        f"job1 (fits the quota share's capacity) is not holding it: {holding[job1]}"
    )
    assert holding[job2] == "RUNNABLE", (
        f"job2 (exceeds the quota share's maxCapacity=1) advanced past RUNNABLE while job1 still "
        f"held the quota share's only unit of ml.m5.large capacity ({holding[job1]}): {holding[job2]}"
    )

    # Restore: force job1 to release its capacity rather than waiting out a full training run,
    # then demand the specific effect -- job2 must be the one to claim the freed capacity.
    batch.terminate_service_job(jobId=job1, reason="sim2real-behavioral-quota-share-restore-leg")
    # Termination stops the underlying training job asynchronously; capacity is released only
    # once job1 is terminal, so wait for that first (bounded) and then for job2 to claim it.
    _poll_until(
        _statuses,
        lambda s: s[job1] in ("SUCCEEDED", "FAILED"),
        timeout_s=300,
        interval_s=5,
    )
    released = _poll_until(
        _statuses,
        lambda s: s[job2] != "RUNNABLE",
        timeout_s=180,
        interval_s=5,
    )
    assert released[job2] in capacity_consuming_states, (
        f"job2 stayed stuck at RUNNABLE even after job1 was terminated and released the quota "
        f"share's capacity, which means the hold was not specifically about capacity: {released[job2]}"
    )


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _submit_with_role_propagation_wait(fn, timeout_s=60.0, interval_s=5.0):
    """Bounded retry for the fresh SageMaker execution role's IAM propagation delay.

    Batch validates RoleArn resolvability at SubmitServiceJob time; a role created moments ago
    can transiently read as unresolvable. Retry only on that specific transient, bounded by a
    deadline, and re-raise immediately on any other rejection.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            if "role" not in str(e).lower() or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_sagemaker_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-smrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess")
    )
    return role["Role"]["Arn"]


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-batch-qs-out-").lower().replace("_", "-")
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in _TAGS.items()]}
    )
    return bucket


def _delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _try_delete_scheduling_policy(ctx, arn: str) -> None:
    batch = ctx.client("batch")
    _retry_delete(lambda: batch.delete_scheduling_policy(arn=arn))


def _drain_and_delete_se(ctx, name: str) -> None:
    batch = ctx.client("batch")
    try:
        batch.update_service_environment(serviceEnvironment=name, state="DISABLED")
        _poll_until(
            lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0],
            lambda se: se["status"] == "VALID",
            timeout_s=90,
            interval_s=4,
        )
        _retry_delete(lambda: batch.delete_service_environment(serviceEnvironment=name))
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


def _drain_and_delete_jq(ctx, name: str) -> None:
    batch = ctx.client("batch")
    try:
        batch.update_job_queue(jobQueue=name, state="DISABLED")
        _poll_until(
            lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"][0],
            lambda jq: jq["status"] == "VALID",
            timeout_s=90,
            interval_s=4,
        )
        _retry_delete(lambda: batch.delete_job_queue(jobQueue=name))
        _wait_jq_gone(batch, name)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


def _try_delete_quota_share(ctx, arn: str) -> None:
    """DeleteQuotaShare requires the share DISABLED first: disable it, wait for the state to settle,
    then delete it."""
    batch = ctx.client("batch")
    try:
        batch.update_quota_share(quotaShareArn=arn, state="DISABLED")
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] == "ClientException" and any(
            f in err.get("Message", "") for f in ("does not exist", "not found for update")
        ):
            return
        raise
    _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=arn),
        lambda d: d["state"] == "DISABLED" and d["status"] in ("VALID", "INVALID"),
        timeout_s=120,
        interval_s=2,
    )
    _retry_delete(lambda: batch.delete_quota_share(quotaShareArn=arn))


def _try_terminate_service_jobs(ctx, job_ids: list[str]) -> None:
    batch = ctx.client("batch")
    for job_id in job_ids:
        try:
            job = batch.describe_service_job(jobId=job_id)
            if job["status"] not in ("SUCCEEDED", "FAILED"):
                batch.terminate_service_job(jobId=job_id, reason="sim2real-behavioral-cleanup")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise


def _retry_delete(fn, timeout_s=300.0):
    """Run a Batch delete; retry its ClientException refusals every 2 s to timeout_s while a
    dependent finishes deleting. A "does not exist" answer is done; every other error raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                return
            if err["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _wait_jq_gone(batch, name, timeout_s=300.0):
    """Poll every 2 s until DescribeJobQueues lists the queue absent or DELETED."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        queues = batch.describe_job_queues(jobQueues=[name])["jobQueues"]
        if not queues or queues[0]["status"] == "DELETED":
            return
        time.sleep(2)
    raise AssertionError(f"job queue {name} still present {timeout_s:.0f}s after DeleteJobQueue")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
