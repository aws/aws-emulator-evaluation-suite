"""service-job-managed-execution-reaches-succeeded."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-job-managed-execution-reaches-succeeded"
GROUP = "server-side"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch"}


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A SAGEMAKER_TRAINING service job reaches SUCCEEDED through Batch <-> SageMaker orchestration.

    The terminal DescribeServiceJob read keeps the job id and a server-assigned createdAt."""
    batch = ctx.client("batch")
    # One teardown deadline per run, started by the first teardown that runs.
    td: dict = {}

    role_arn = _create_sagemaker_execution_role(ctx, "sim2real-batch-smrole-")
    bucket = _create_output_bucket(ctx, "sim2real-batch-smout-")

    sp = batch.create_scheduling_policy(
        name=ctx.unique_name("sim2real-batch-smsp-"),
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags=dict(_MANAGED_TAGS),
    )
    sp_arn = sp["arn"]
    ctx.on_cleanup(lambda: _delete_scheduling_policy(ctx, sp_arn, td))

    se_name = ctx.unique_name("sim2real-batch-se-")
    batch.create_service_environment(
        serviceEnvironmentName=se_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"maxCapacity": 1, "capacityUnit": "ml.m5.large"}],
        tags=dict(_MANAGED_TAGS),
    )
    ctx.on_cleanup(lambda: _disable_and_delete_service_environment(ctx, se_name, td))
    _wait_for_service_environment_status(ctx, se_name, "VALID", timeout_s=180)

    jq_name = ctx.unique_name("sim2real-batch-jq-")
    batch.create_job_queue(
        jobQueueName=jq_name,
        priority=1,
        jobQueueType="SAGEMAKER_TRAINING",
        schedulingPolicyArn=sp_arn,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": se_name}],
        tags=dict(_MANAGED_TAGS),
    )
    ctx.on_cleanup(lambda: _disable_and_delete_job_queue(ctx, jq_name, td))
    _wait_for_job_queue_status(ctx, jq_name, "VALID", timeout_s=180)

    quota_share = ctx.unique_name("sim2real-batch-smqs-")
    qs = batch.create_quota_share(
        quotaShareName=quota_share,
        jobQueue=jq_name,
        capacityLimits=[{"maxCapacity": 1, "capacityUnit": "ml.m5.large"}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        tags=dict(_MANAGED_TAGS),
    )
    qs_arn = qs["quotaShareArn"]
    ctx.on_cleanup(lambda: _disable_and_delete_quota_share(ctx, qs_arn, td))
    _wait_for_quota_share_status(ctx, qs_arn, "VALID", timeout_s=120)

    training_image = f"763104351884.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-training:2.0.0-cpu-py310"
    payload = {
        "TrainingJobName": ctx.unique_name("sim2real-batch-tj-"),
        "RoleArn": role_arn,
        "AlgorithmSpecification": {
            "TrainingInputMode": "File",
            "TrainingImage": training_image,
            "ContainerEntrypoint": ["echo", "hello-from-sim2real-batch"],
        },
        "ResourceConfig": {"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 1},
        "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/output"},
        "StoppingCondition": {"MaxRuntimeInSeconds": 180},
    }
    submit = _submit_service_job_with_retry(
        batch,
        jobName=ctx.unique_name("sim2real-batch-sj-"),
        jobQueue=jq_name,
        serviceJobType="SAGEMAKER_TRAINING",
        quotaShareName=quota_share,
        schedulingPriority=1,
        serviceRequestPayload=json.dumps(payload),
        tags=dict(_MANAGED_TAGS),
    )
    job_id = submit["jobId"]
    # Batch runs the service job as a SageMaker training job it names itself and reports on each
    # attempt's serviceResourceId; the training job and its trial components outlive the service
    # job and must be deleted separately. Registered before the terminate, so the job is stopped
    # before its artifacts are deleted.
    artifacts_deleted: list[bool] = []
    ctx.on_cleanup(lambda: _delete_sagemaker_training_artifacts_quiet(ctx, job_id, artifacts_deleted, td))
    ctx.on_cleanup(lambda: _terminate_service_job_quiet(ctx, job_id))

    final = _wait_for_service_job_terminal(ctx, job_id, timeout_s=900, interval_s=15)
    assert final["status"] == "SUCCEEDED", (
        f"service job did not reach SUCCEEDED purely via server orchestration: "
        f"status={final['status']!r} reason={final.get('statusReason')!r}"
    )
    assert final.get("jobId") == job_id, f"terminal read job id mismatch: expected {job_id!r}, got {final.get('jobId')!r}"
    assert final.get("createdAt"), "expected a server-assigned createdAt timestamp on the terminal job"

    job_arns = _training_job_arns(final)
    assert job_arns, f"SUCCEEDED service job {job_id} reports no TrainingJobArn attempt: {final!r}"
    # Both artifacts appear asynchronously after SUCCEEDED, so each delete waits for its target.
    _delete_sagemaker_training_artifacts(ctx, job_arns)
    artifacts_deleted.append(True)

    # Deletes take effect lazily (DeleteJobQueue right after DeleteQuotaShare still 400s), so
    # each dependency is waited gone in order: quota share -> job queue -> environment, policy.
    _disable_and_delete_quota_share(ctx, qs_arn)
    _disable_and_delete_job_queue(ctx, jq_name)
    _disable_and_delete_service_environment(ctx, se_name)
    _delete_scheduling_policy(ctx, sp_arn)


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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=_tags_kv()
    )
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        _delete_quiet(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
        _delete_quiet(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    return role["Role"]["Arn"]


def _submit_service_job_with_retry(batch, *, attempts: int = 6, delay_s: float = 10.0, **kwargs):
    """SubmitServiceJob can reject with ClientException while the just-created execution
    role's trust/attachment has not yet propagated far enough for SageMaker to assume it;
    retry the submission itself on that specific error."""
    last_err = None
    for _ in range(attempts):
        try:
            return batch.submit_service_job(**kwargs)
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] != "ClientException":
                raise
            time.sleep(delay_s)
    raise AssertionError(f"submit_service_job never succeeded after retries: {last_err}")


def _create_output_bucket(ctx: Any, prefix: str) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix).lower()
    kwargs: dict[str, Any] = {"Bucket": bucket}
    # S3 rejects CreateBucketConfiguration for us-east-1 specifically (the API's original
    # region), regardless of account; every other region requires it. Not account-specific.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_kv()})

    def _cleanup() -> None:
        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket):
                for obj in page.get("Contents", []):
                    s3.delete_object(Bucket=bucket, Key=obj["Key"])
        except ClientError as exc:
            if not _gone(exc):
                raise
        _delete_quiet(lambda: s3.delete_bucket(Bucket=bucket))

    ctx.on_cleanup(_cleanup)
    return bucket


def _wait_for_service_environment_status(ctx: Any, name: str, status: str, *, timeout_s: float) -> None:
    batch = ctx.client("batch")

    def _probe():
        resp = batch.describe_service_environments(serviceEnvironments=[name])
        envs = resp.get("serviceEnvironments", [])
        return envs[0] if envs else None

    # _wait_until already raises on timeout and only returns once r["status"] == status
    # holds, so a trailing re-assertion of that same predicate here can never fail.
    _wait_until(_probe, lambda r: r is not None and r["status"] == status, timeout_s=timeout_s, interval_s=3)


def _wait_for_job_queue_status(ctx: Any, name: str, status: str, *, timeout_s: float) -> None:
    batch = ctx.client("batch")

    def _probe():
        resp = batch.describe_job_queues(jobQueues=[name])
        queues = resp.get("jobQueues", [])
        return queues[0] if queues else None

    _wait_until(_probe, lambda r: r is not None and r["status"] == status, timeout_s=timeout_s, interval_s=3)


def _wait_for_quota_share_status(ctx: Any, arn: str, status: str, *, timeout_s: float) -> None:
    batch = ctx.client("batch")

    def _probe():
        return batch.describe_quota_share(quotaShareArn=arn)

    _wait_until(_probe, lambda r: r["status"] == status, timeout_s=timeout_s, interval_s=3)


def _gone(exc: ClientError) -> bool:
    """Whether a teardown call's error says its target is already absent."""
    err = exc.response["Error"]
    message = err.get("Message", "").lower()
    if err["Code"] in ("NoSuchEntity", "NoSuchBucket", "ResourceNotFound"):
        return True
    return err["Code"] in ("ClientException", "ValidationException") and (
        "does not exist" in message or "not found" in message
    )


def _delete_quiet(fn) -> None:
    """Run a teardown call; an already-absent target is done and every other error raises."""
    try:
        fn()
    except ClientError as exc:
        if not _gone(exc):
            raise


def _live(items: list) -> dict | None:
    """The first listed resource, or None when it is absent or already deleting."""
    if not items or "DELET" in str(items[0].get("status") or "").upper():
        return None
    return items[0]


# Inside the 900 s batch cleanup budget, one deadline shared by every teardown of a run.
_TEARDOWN_S = 780.0


def _cap(td: dict | None, own_s: float) -> float:
    """own_s, cut to what is left of the run's shared teardown deadline when td is given."""
    if td is None:
        return own_s
    deadline = td.setdefault("t", time.monotonic() + _TEARDOWN_S)
    return max(0.0, min(own_s, deadline - time.monotonic()))


def _wait_until_gone(probe, *, timeout_s: float, interval_s: float = 5.0) -> None:
    """Poll until `probe()` reports the resource absent (None), not just until its delete returned."""
    _wait_until(probe, lambda r: r is None, timeout_s=timeout_s, interval_s=interval_s)


def _disable_and_delete_service_environment(ctx: Any, name: str, td: dict | None = None) -> None:
    batch = ctx.client("batch")

    def _describe():
        return _live(batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"])

    if _describe() is None:
        return
    batch.update_service_environment(serviceEnvironment=name, state="DISABLED")
    # DeleteServiceEnvironment needs "state" (not "status") settled to DISABLED: "status" stays
    # VALID across the disable, so waiting on it lets the delete 400 on an ENABLED environment.
    _wait_until(_describe, lambda r: r is None or r["state"] == "DISABLED", timeout_s=_cap(td, 120), interval_s=3)
    _retry_delete(lambda: batch.delete_service_environment(serviceEnvironment=name), timeout_s=_cap(td, 300))
    _wait_until_gone(_describe, timeout_s=_cap(td, 120))


def _disable_and_delete_job_queue(ctx: Any, name: str, td: dict | None = None) -> None:
    batch = ctx.client("batch")

    def _describe():
        return _live(batch.describe_job_queues(jobQueues=[name])["jobQueues"])

    if _describe() is None:
        return
    batch.update_job_queue(jobQueue=name, state="DISABLED")
    # Same state-vs-status distinction as the service environment: DeleteJobQueue
    # needs state == DISABLED, not status == VALID.
    _wait_until(_describe, lambda r: r is None or r["state"] == "DISABLED", timeout_s=_cap(td, 120), interval_s=3)
    _retry_delete(lambda: batch.delete_job_queue(jobQueue=name), timeout_s=_cap(td, 300))
    # The scheduling policy and (via the caller's ordering) the service environment
    # this queue references cannot delete while Batch still sees it -- wait for gone,
    # not just for the delete call to return.
    _wait_until_gone(_describe, timeout_s=_cap(td, 120))


def _disable_and_delete_quota_share(ctx: Any, arn: str, td: dict | None = None) -> None:
    batch = ctx.client("batch")

    def _describe():
        try:
            return _live([batch.describe_quota_share(quotaShareArn=arn)])
        except ClientError as exc:
            if _gone(exc):
                return None
            raise

    if _describe() is None:
        return
    # DeleteQuotaShare requires the quota share to be DISABLED first (mirrors
    # DeleteJobQueue's own disable-before-delete requirement) -- wait for that state
    # transition to settle rather than relying on delete-retry backoff alone.
    batch.update_quota_share(quotaShareArn=arn, state="DISABLED")
    _wait_until(_describe, lambda r: r is None or r["state"] == "DISABLED", timeout_s=_cap(td, 120), interval_s=3)
    _retry_delete(lambda: batch.delete_quota_share(quotaShareArn=arn), timeout_s=_cap(td, 300))
    # The job queue this quota share references cannot delete while Batch still sees
    # this relationship -- wait for gone, not just for the delete call to return.
    _wait_until_gone(_describe, timeout_s=_cap(td, 120))


def _delete_scheduling_policy(ctx: Any, arn: str, td: dict | None = None) -> None:
    batch = ctx.client("batch")
    if batch.describe_scheduling_policies(arns=[arn])["schedulingPolicies"]:
        _retry_delete(lambda: batch.delete_scheduling_policy(arn=arn), timeout_s=_cap(td, 300))


def _retry_delete(fn, *, timeout_s: float = 300.0) -> None:
    """Run a Batch delete; retry its ClientException refusals every 2 s to timeout_s while a
    dependent finishes deleting or a terminated job releases its capacity. An already-absent
    target is done; every other error raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if _gone(exc):
                return
            if exc.response["Error"]["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _terminate_service_job_quiet(ctx: Any, job_id: str) -> None:
    """TerminateServiceJob; Batch accepts it for a job that is already terminal."""
    batch = ctx.client("batch")
    batch.terminate_service_job(jobId=job_id, reason="sim2real-behavioral-cleanup")


_TRAINING_TERMINAL = {"Completed", "Failed", "Stopped"}


def _training_job_arns(service_job: dict) -> list[str]:
    """The SageMaker training job ARNs a DescribeServiceJob response reports for its attempts."""
    attempts = list(service_job.get("attempts") or [])
    if service_job.get("latestAttempt"):
        attempts.append(service_job["latestAttempt"])
    return sorted({
        a["serviceResourceId"]["value"]
        for a in attempts
        if (a.get("serviceResourceId") or {}).get("name") == "TrainingJobArn"
    })


def _delete_sagemaker_training_artifacts_quiet(ctx: Any, job_id: str, deleted: list, td: dict | None = None) -> None:
    """Delete the training jobs and their trial components when `run` raised before deleting them.

    Each training job is first waited to a terminal status, as SageMaker deletes only a stopped job."""
    if deleted:
        return
    sm = ctx.client("sagemaker")
    service_job = ctx.client("batch").describe_service_job(jobId=job_id)
    for job_arn in _training_job_arns(service_job):
        name = job_arn.split("/")[-1]

        def _job(name=name):
            try:
                return sm.describe_training_job(TrainingJobName=name)
            except ClientError as exc:
                if _gone(exc):
                    return None
                raise

        job = _wait_until(
            _job, lambda j: j is None or j["TrainingJobStatus"] in _TRAINING_TERMINAL, timeout_s=_cap(td, 300),
            interval_s=2,
        )
        if job is None:
            continue
        _delete_trial_components(sm, job_arn, timeout_s=_cap(td, 120))
        _delete_quiet(lambda name=name: sm.delete_training_job(TrainingJobName=name))


def _delete_trial_components(sm, training_job_arn: str, *, timeout_s: float = 120.0) -> None:
    """Delete the trial components SageMaker lists for the training job. SageMaker creates one
    for every training job asynchronously, so the listing is polled every 5 s until one appears;
    none by the deadline raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        listed = sm.list_trial_components(SourceArn=training_job_arn)["TrialComponentSummaries"]
        if listed:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"no trial component listed for {training_job_arn} within {timeout_s:.0f}s")
        time.sleep(5)
    for component in listed:
        _delete_quiet(lambda n=component["TrialComponentName"]: sm.delete_trial_component(TrialComponentName=n))


def _poll_delete_until_exists(fn, *, timeout_s: float, interval_s: float = 10.0) -> None:
    """Retry a delete only while it fails because the target does not exist yet.

    Not-yet-created reads as a "not found" ValidationException; every other error raises, and so
    does a target still absent at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            if not _gone(err) or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _delete_sagemaker_training_artifacts(ctx: Any, job_arns: list[str], *, timeout_s: float = 240.0) -> None:
    """Delete each SageMaker training job Batch created, plus the trial components listed for it.

    SageMaker creates the job asynchronously, so its read and its delete are polled until it exists."""
    sm = ctx.client("sagemaker")
    for arn in job_arns:
        name = arn.split("/")[-1]
        job_arn = _poll_training_job_arn(sm, name, timeout_s=timeout_s)
        _delete_trial_components(sm, job_arn)
        _poll_delete_until_exists(
            lambda name=name: sm.delete_training_job(TrainingJobName=name), timeout_s=timeout_s
        )


def _poll_training_job_arn(sm, training_job_name: str, *, timeout_s: float, interval_s: float = 10.0) -> str:
    """The training job's ARN, polled while the job does not exist yet; any other error raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sm.describe_training_job(TrainingJobName=training_job_name)["TrainingJobArn"]
        except ClientError as err:
            if not _gone(err) or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _wait_for_service_job_terminal(ctx: Any, job_id: str, *, timeout_s: float, interval_s: float) -> dict:
    batch = ctx.client("batch")
    terminal = {"SUCCEEDED", "FAILED"}

    def _probe():
        return batch.describe_service_job(jobId=job_id)

    return _wait_until(_probe, lambda r: r["status"] in terminal, timeout_s=timeout_s, interval_s=interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
