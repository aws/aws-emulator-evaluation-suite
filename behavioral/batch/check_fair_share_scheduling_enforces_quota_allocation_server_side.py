"""fair-share-scheduling-enforces-quota-allocation-server-side."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fair-share-scheduling-enforces-quota-allocation-server-side"
GROUP = "server-side"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """Under a quota-management scheduling policy, GetJobQueueSnapshot attributes the head-of-line
    RUNNABLE job to the correct quota share, so the scheduler enforces dispatch order server-
    side."""
    batch = ctx.client("batch")

    role_arn = _create_sagemaker_execution_role(ctx, "sim2real-batch-fsrole-")


    bucket = _create_output_bucket(ctx, "sim2real-batch-fsout-")

    sp = batch.create_scheduling_policy(
        name=ctx.unique_name("sim2real-batch-sp-"),
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags={"sim2real": CHECK},
    )
    sp_arn = sp["arn"]
    ctx.on_cleanup(lambda: _delete_quiet(lambda: batch.delete_scheduling_policy(arn=sp_arn)))

    se_name = ctx.unique_name("sim2real-batch-se-")
    batch.create_service_environment(
        serviceEnvironmentName=se_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"maxCapacity": 2, "capacityUnit": "ml.m5.large"}],
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _disable_and_delete_service_environment(ctx, se_name))
    _wait_for_service_environment_status(ctx, se_name, "VALID", timeout_s=180)

    jq_name = ctx.unique_name("sim2real-batch-jq-")
    batch.create_job_queue(
        jobQueueName=jq_name,
        priority=1,
        jobQueueType="SAGEMAKER_TRAINING",
        schedulingPolicyArn=sp_arn,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": se_name}],
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _disable_and_delete_job_queue(ctx, jq_name))
    _wait_for_job_queue_status(ctx, jq_name, "VALID", timeout_s=180)

    share_a = ctx.unique_name("sim2real-fs-a-")
    share_b = ctx.unique_name("sim2real-fs-b-")
    arn_a = _create_quota_share(ctx, share_a, jq_name)
    arn_b = _create_quota_share(ctx, share_b, jq_name)
    _wait_for_quota_share_status(ctx, arn_a, "VALID", timeout_s=120)
    _wait_for_quota_share_status(ctx, arn_b, "VALID", timeout_s=120)

    job_arns_a = []
    job_arns_b = []
    for share_name, bucket_of, out in ((share_a, job_arns_a, "a"), (share_b, job_arns_b, "b")):
        for i in range(2):
            submit = _submit_service_job_retrying_role_propagation(
                ctx, jq_name, role_arn, bucket, share_name, f"{out}{i}"
            )
            bucket_of.append(submit["jobArn"])
            ctx.on_cleanup(lambda jid=submit["jobId"]: _terminate_service_job_quiet(ctx, jid))

    snapshot = _wait_for_quota_share_fronts(ctx, jq_name, {share_a, share_b}, timeout_s=90)
    fronts = snapshot["frontOfQuotaShares"]["quotaShares"]

    assert set(fronts.keys()) == {share_a, share_b}, (
        f"expected independent per-quota-share head-of-line tracking for both shares, got {sorted(fronts)}"
    )
    front_a_arn = fronts[share_a][0]["jobArn"]
    front_b_arn = fronts[share_b][0]["jobArn"]
    assert front_a_arn in job_arns_a, "quota share A's front-of-line job must belong to share A"
    assert front_b_arn in job_arns_b, "quota share B's front-of-line job must belong to share B"
    assert front_a_arn != front_b_arn, (
        "the scheduler must maintain a distinct head-of-line job per quota share "
        "(the client never picked which job is 'first' per share)"
    )


def _wait_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_sagemaker_execution_role(ctx: Any, prefix: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
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
    return role["Role"]["Arn"]


def _create_output_bucket(ctx: Any, prefix: str) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix).lower()
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup() -> None:
        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket):
                for obj in page.get("Contents", []):
                    s3.delete_object(Bucket=bucket, Key=obj["Key"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        try:
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


def _wait_for_service_environment_status(ctx: Any, name: str, status: str, *, timeout_s: float) -> None:
    batch = ctx.client("batch")

    def _probe():
        resp = batch.describe_service_environments(serviceEnvironments=[name])
        envs = resp.get("serviceEnvironments", [])
        return envs[0] if envs else None

    result = _wait_until(_probe, lambda r: r is not None and r["status"] == status, timeout_s=timeout_s, interval_s=3)
    assert result["status"] == status


def _wait_for_job_queue_status(ctx: Any, name: str, status: str, *, timeout_s: float) -> None:
    batch = ctx.client("batch")

    def _probe():
        resp = batch.describe_job_queues(jobQueues=[name])
        queues = resp.get("jobQueues", [])
        return queues[0] if queues else None

    result = _wait_until(_probe, lambda r: r is not None and r["status"] == status, timeout_s=timeout_s, interval_s=3)
    assert result["status"] == status


def _wait_for_quota_share_status(ctx: Any, arn: str, status: str, *, timeout_s: float) -> None:
    batch = ctx.client("batch")

    def _probe():
        return batch.describe_quota_share(quotaShareArn=arn)

    result = _wait_until(_probe, lambda r: r["status"] == status, timeout_s=timeout_s, interval_s=3)
    assert result["status"] == status


def _create_quota_share(ctx: Any, name: str, job_queue: str) -> str:
    batch = ctx.client("batch")
    resp = batch.create_quota_share(
        quotaShareName=name,
        jobQueue=job_queue,
        capacityLimits=[{"maxCapacity": 1, "capacityUnit": "ml.m5.large"}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        tags={"sim2real": CHECK},
    )
    arn = resp["quotaShareArn"]
    ctx.on_cleanup(lambda: _disable_and_delete_quota_share(batch, arn))
    return arn


def _disable_and_delete_quota_share(batch, arn: str) -> None:
    # DeleteQuotaShare requires the quota share to be DISABLED first (mirrors
    # DeleteJobQueue's own disable-before-delete requirement).
    try:
        batch.update_quota_share(quotaShareArn=arn, state="DISABLED")
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ClientException"
            and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
        ):
            raise
    _retry_delete(lambda: batch.delete_quota_share(quotaShareArn=arn))



def _submit_service_job(ctx: Any, job_queue: str, role_arn: str, bucket: str, quota_share_name: str, tag: str):
    batch = ctx.client("batch")
    training_image = f"763104351884.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-training:2.0.0-cpu-py310"
    payload = {
        "TrainingJobName": ctx.unique_name(f"sim2real-batch-tj-{tag}-"),
        "RoleArn": role_arn,
        "AlgorithmSpecification": {
            "TrainingInputMode": "File",
            "TrainingImage": training_image,
            "ContainerEntrypoint": ["echo", f"hello-from-sim2real-batch-{tag}"],
        },
        "ResourceConfig": {"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 1},
        "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/output/{tag}"},
        "StoppingCondition": {"MaxRuntimeInSeconds": 180},
    }
    return batch.submit_service_job(
        jobName=ctx.unique_name(f"sim2real-batch-sj-{tag}-"),
        jobQueue=job_queue,
        serviceJobType="SAGEMAKER_TRAINING",
        quotaShareName=quota_share_name,
        schedulingPriority=1,
        serviceRequestPayload=json.dumps(payload),
    )


def _submit_service_job_retrying_role_propagation(
    ctx: Any, job_queue: str, role_arn: str, bucket: str, quota_share_name: str, tag: str, *, timeout_s: float = 60.0
):
    """The execution role is created moments earlier in this same run; IAM's attach-policy
    propagation is eventually consistent, so retry the FIRST call that actually depends on the
    role (this submission) on the specific rejection until it succeeds, instead of guessing a
    fixed sleep upfront."""
    deadline = time.monotonic() + timeout_s
    last: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return _submit_service_job(ctx, job_queue, role_arn, bucket, quota_share_name, tag)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in {"ClientException", "InvalidParameterValueException"}:
                raise
            last = exc
            time.sleep(5.0)
    raise AssertionError(
        f"submit_service_job never accepted role {role_arn} within {timeout_s}s (last={last!r})"
    )


def _wait_for_quota_share_fronts(ctx: Any, job_queue: str, expected_shares: set, *, timeout_s: float) -> dict:
    batch = ctx.client("batch")

    def _probe():
        return batch.get_job_queue_snapshot(jobQueue=job_queue)

    def _ready(snap) -> bool:
        shares = snap.get("frontOfQuotaShares", {}).get("quotaShares", {})
        return expected_shares.issubset(shares.keys()) and all(shares[s] for s in expected_shares)

    return _wait_until(_probe, _ready, timeout_s=timeout_s, interval_s=3)


def _disable_and_delete_service_environment(ctx: Any, name: str) -> None:
    batch = ctx.client("batch")
    try:
        batch.update_service_environment(serviceEnvironment=name, state="DISABLED")
        _wait_for_service_environment_status(ctx, name, "VALID", timeout_s=120)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    batch.delete_service_environment(serviceEnvironment=name)


def _disable_and_delete_job_queue(ctx: Any, name: str) -> None:
    batch = ctx.client("batch")
    try:
        batch.update_job_queue(jobQueue=name, state="DISABLED")
        _wait_for_job_queue_status(ctx, name, "VALID", timeout_s=60)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    # By this point the quota-share cleanups registered via _create_quota_share
    # have already run (ctx.on_cleanup is LIFO, and quota shares are registered
    # after the job queue), so DeleteJobQueue's "quota share still attached"
    # dependency is normally already clear; retry absorbs any residual lag.
    _retry_delete(lambda: batch.delete_job_queue(jobQueue=name))





def _terminate_service_job_quiet(ctx: Any, job_id: str) -> None:
    batch = ctx.client("batch")
    batch.terminate_service_job(jobId=job_id, reason="sim2real-behavioral-cleanup")


def _delete_quiet(fn) -> None:
    fn()


def _retry_delete(fn, *, attempts: int = 5, delay_s: float = 8.0) -> None:
    """Best-effort delete with retries: AWS Batch quota-share/job-queue deletes can
    transiently fail with ClientException while a just-terminated service job is
    still releasing its capacity reservation. Swallows the final failure too (this
    runs from ctx.on_cleanup, where raising would mask the check's real result)."""
    for attempt in range(attempts):
        try:
            fn()
            return
        except Exception:
            if attempt == attempts - 1:
                return
            time.sleep(delay_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
