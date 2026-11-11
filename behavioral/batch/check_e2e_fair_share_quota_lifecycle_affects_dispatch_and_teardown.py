"""e2e-fair-share-quota-lifecycle-affects-dispatch-and-teardown."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-fair-share-quota-lifecycle-affects-dispatch-and-teardown"
GROUP = "e2e"
SERVICES = ["batch"]

_CAPACITY_UNIT = "ml.c5.xlarge"
_TAGS = {"sim2real": CHECK}
_ROLE_PROPAGATION_DEADLINE_S = 120.0
# Each training job sleeps this long once placed, so teamHigh's job holds the sole unit until
# the check terminates it explicitly to release the unit.
_HOLD_S = 600
_JOB_DEADLINE_S = 900  # MaxRuntimeInSeconds and attemptDurationSeconds, above _HOLD_S


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """While one quota share's job holds a service environment's sole unit of capacity, another
    share's job on the same queue stays queued; terminating the first dispatches it without
    re-submission, and teardown leaves no job active.
    """
    batch = ctx.client("batch")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-batch-quota-").replace("_", "-")
    # S3 CreateBucket rejects an explicit LocationConstraint of us-east-1 itself (that region is
    # the one case where omitting the member is the only legal request shape).
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in _TAGS.items()]})

    role_name = ctx.unique_name("sim2real-batch-quota-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess")
    role_ready_deadline = time.monotonic() + _ROLE_PROPAGATION_DEADLINE_S

    policy_name = ctx.unique_name("sim2real-batch-quota-policy-")
    policy = batch.create_scheduling_policy(
        name=policy_name, quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"}, tags=_TAGS
    )
    policy_arn = policy["arn"]
    ctx.on_cleanup(lambda: _delete_scheduling_policy(ctx, policy_arn))

    se_name = ctx.unique_name("sim2real-batch-quota-se-")
    batch.create_service_environment(
        serviceEnvironmentName=se_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"maxCapacity": 1, "capacityUnit": _CAPACITY_UNIT}],
        tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _disable_and_delete_service_environment(ctx, se_name))
    se_arn = _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[se_name])["serviceEnvironments"][0],
        lambda se: se["status"] == "VALID",
        timeout_s=60.0,
    )["serviceEnvironmentArn"]

    jq_name = ctx.unique_name("sim2real-batch-quota-jq-")
    batch.create_job_queue(
        jobQueueName=jq_name,
        priority=1,
        jobQueueType="SAGEMAKER_TRAINING",
        schedulingPolicyArn=policy_arn,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": se_arn}],
        tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _disable_and_delete_job_queue(ctx, jq_name))
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[jq_name])["jobQueues"][0],
        lambda jq: jq["status"] == "VALID",
        timeout_s=60.0,
    )

    high_share = batch.create_quota_share(
        quotaShareName="teamHigh",
        jobQueue=jq_name,
        capacityLimits=[{"maxCapacity": 1, "capacityUnit": _CAPACITY_UNIT}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "ENABLED"},
        tags=_TAGS,
    )
    high_arn = high_share["quotaShareArn"]
    ctx.on_cleanup(lambda: _disable_and_delete_quota_share(ctx, high_arn))

    low_share = batch.create_quota_share(
        quotaShareName="teamLow",
        jobQueue=jq_name,
        capacityLimits=[{"maxCapacity": 1, "capacityUnit": _CAPACITY_UNIT}],
        resourceSharingConfiguration={"strategy": "LEND"},
        preemptionConfiguration={"inSharePreemption": "ENABLED"},
        tags=_TAGS,
    )
    low_arn = low_share["quotaShareArn"]
    ctx.on_cleanup(lambda: _disable_and_delete_quota_share(ctx, low_arn))

    for arn in (high_arn, low_arn):
        _poll_until(
            lambda arn=arn: batch.describe_quota_share(quotaShareArn=arn),
            lambda qs: qs["status"] == "VALID",
            timeout_s=60.0,
        )

    def _submit_job(share: str) -> str:
        name = ctx.unique_name(f"sim2real-batch-quota-{share.lower()}-")
        submitted = batch.submit_service_job(
            jobName=name,
            jobQueue=jq_name,
            serviceJobType="SAGEMAKER_TRAINING",
            quotaShareName=share,
            schedulingPriority=1,
            serviceRequestPayload=_training_payload(name, role_arn, bucket, ctx.region),
            retryStrategy={"attempts": 1},
            timeoutConfig={"attemptDurationSeconds": _JOB_DEADLINE_S},
            tags=_TAGS,
        )
        job_id = submitted["jobId"]
        ctx.on_cleanup(lambda job_id=job_id: _terminate_and_wait_service_job(ctx, job_id))
        return job_id

    # teamHigh's job is dispatched onto the sole unit and reaches RUNNING, where its _HOLD_S sleep
    # keeps it holding the unit. A FAILED whose reason names the just-created role is SageMaker
    # hitting IAM/STS trust-policy propagation lag, not a capacity problem -- resubmit (a fresh
    # job, since a terminal job cannot be revived) bounded by role_ready_deadline, measured from
    # role creation. Any other FAILED reason, or a role-shaped failure past the deadline, fails.
    high_job_id = _submit_job("teamHigh")
    while True:
        high_final = _poll_until(
            lambda: batch.describe_service_job(jobId=high_job_id),
            lambda j: j["status"] in ("RUNNING", "SUCCEEDED", "FAILED"),
            timeout_s=900.0,
            interval_s=15.0,
        )
        if high_final["status"] != "FAILED":
            break
        reason = high_final.get("statusReason") or ""
        if time.monotonic() < role_ready_deadline and _looks_like_role_propagation_failure(reason):
            high_job_id = _submit_job("teamHigh")
            continue
        break
    assert high_final["status"] == "RUNNING", (
        f"teamHigh's job must be dispatched and hold the unit (RUNNING, inside its {_HOLD_S}s "
        f"sleep): {high_final['status']} / {high_final.get('statusReason')}"
    )

    # teamLow's job competes for the unit teamHigh's job holds.
    low_job_id = _submit_job("teamLow")
    snap = _poll_until(
        lambda: batch.get_job_queue_snapshot(jobQueue=jq_name),
        lambda s: "teamLow" in s.get("frontOfQuotaShares", {}).get("quotaShares", {}),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert "teamLow" in snap["frontOfQuotaShares"]["quotaShares"], (
        f"teamLow's withheld job missing from the job-queue snapshot: {snap!r}"
    )
    low_snapshot = batch.describe_service_job(jobId=low_job_id)
    assert low_snapshot["status"] in ("SUBMITTED", "PENDING", "RUNNABLE"), (
        f"teamLow's job dispatched while the sole unit is held by teamHigh's running job: "
        f"{low_snapshot['status']} / {low_snapshot.get('statusReason')}"
    )
    # teamHigh is re-read AFTER the teamLow read, so that read fell while the unit was held.
    high_after = batch.describe_service_job(jobId=high_job_id)
    assert high_after["status"] == "RUNNING", (
        f"teamHigh's job left RUNNING before teamLow was read, so the queued read proves "
        f"nothing: {high_after['status']!r}"
    )

    # Releasing the unit must dispatch teamLow's already-submitted job.
    batch.terminate_service_job(jobId=high_job_id, reason="sim2real-release-unit")
    _poll_until(
        lambda: batch.describe_service_job(jobId=high_job_id),
        lambda j: j["status"] in ("SUCCEEDED", "FAILED"),
        timeout_s=300.0,
        interval_s=10.0,
    )
    low_dispatched = _poll_until(
        lambda: batch.describe_service_job(jobId=low_job_id),
        lambda j: j["status"] in ("RUNNING", "SUCCEEDED", "FAILED"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert low_dispatched["status"] == "RUNNING", (
        f"teamLow's withheld job must be dispatched once the unit is released, with no "
        f"re-submission: {low_dispatched['status']} / {low_dispatched.get('statusReason')}"
    )
    # Absence by contrast: teamLow never ran while teamHigh held the unit.
    high_stopped = batch.describe_service_job(jobId=high_job_id).get("stoppedAt")
    low_started = low_dispatched.get("startedAt")
    assert isinstance(high_stopped, int) and isinstance(low_started, int), (
        f"a stopped job reports stoppedAt and a running job startedAt: teamHigh stoppedAt="
        f"{high_stopped!r}, teamLow startedAt={low_started!r}"
    )
    assert low_started >= high_stopped, (
        f"teamLow's job started at {low_started}, before teamHigh's job released the sole unit "
        f"at {high_stopped}"
    )

    # Teardown: terminate both jobs and confirm neither is left active before deleting resources.
    batch.terminate_service_job(jobId=low_job_id, reason="sim2real-behavioral-teardown")
    for job_id in (high_job_id, low_job_id):
        _poll_until(
            lambda job_id=job_id: batch.describe_service_job(jobId=job_id),
            lambda j: j["status"] in ("SUCCEEDED", "FAILED"),
            timeout_s=300.0,
            interval_s=10.0,
        )

    remaining_active = [
        j
        for j in batch.list_service_jobs(jobQueue=jq_name)["jobSummaryList"]
        if j["jobId"] in (high_job_id, low_job_id) and j["status"] not in ("SUCCEEDED", "FAILED")
    ]
    assert remaining_active == [], f"orphaned active jobs after teardown: {remaining_active}"

    _disable_and_delete_quota_share(ctx, high_arn)
    _disable_and_delete_quota_share(ctx, low_arn)
    _disable_and_delete_job_queue(ctx, jq_name)

    # DeleteJobQueue is asynchronous: the queue can keep appearing in DescribeJobQueues for a
    # while after the call returns, so this bounds the wait instead of asserting immediately.
    deadline = time.monotonic() + 180.0
    remaining_queues = batch.describe_job_queues(jobQueues=[jq_name])["jobQueues"]
    while remaining_queues and time.monotonic() < deadline:
        time.sleep(5.0)
        remaining_queues = batch.describe_job_queues(jobQueues=[jq_name])["jobQueues"]
    assert remaining_queues == [], (
        f"job queue still present after delete -- teardown did not complete: {remaining_queues}"
    )


def _training_payload(name: str, role_arn: str, bucket: str, region: str) -> str:
    return json.dumps(
        {
            "TrainingJobName": name,
            "RoleArn": role_arn,
            "AlgorithmSpecification": {
                "TrainingInputMode": "File",
                # A non-ECR registry (public.ecr.aws, Docker Hub, ...) is a "private Docker
                # registry" from SageMaker's point of view and is rejected unless
                # TrainingImageConfig/TrainingRepositoryAccessMode=Vpc is also supplied; the AWS
                # Deep Learning Container images in this well-known ECR account need neither.
                "TrainingImage": f"763104351884.dkr.ecr.{region}.amazonaws.com/pytorch-training:2.0.0-cpu-py310",
                "ContainerEntrypoint": ["sleep", str(_HOLD_S)],
            },
            "ResourceConfig": {"InstanceType": _CAPACITY_UNIT, "InstanceCount": 1, "VolumeSizeInGB": 1},
            "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/output"},
            "StoppingCondition": {"MaxRuntimeInSeconds": _JOB_DEADLINE_S},
        }
    )


# ===== helpers =====
def _looks_like_role_propagation_failure(reason: str) -> bool:
    lowered = reason.lower()
    return any(s in lowered for s in ("assumerole", "assume role", "not authorized", "accessdenied"))


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=5.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _terminate_and_wait_service_job(ctx, job_id: str) -> None:
    batch = ctx.client("batch")
    if batch.describe_service_job(jobId=job_id)["status"] in ("SUCCEEDED", "FAILED"):
        return
    batch.terminate_service_job(jobId=job_id, reason="sim2real-behavioral-cleanup")
    _poll_until(
        lambda: batch.describe_service_job(jobId=job_id),
        lambda j: j["status"] in ("SUCCEEDED", "FAILED"),
        timeout_s=180.0,
        interval_s=2.0,
    )


def _disable_and_delete_quota_share(ctx, arn: str) -> None:
    batch = ctx.client("batch")
    if _quota_share_gone(batch, arn):
        return
    batch.update_quota_share(quotaShareArn=arn, state="DISABLED")
    _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=arn),
        lambda qs: qs["status"] == "VALID" and qs["state"] == "DISABLED",
        timeout_s=60.0,
    )
    batch.delete_quota_share(quotaShareArn=arn)
    # DeleteQuotaShare is asynchronous, and the job queue cannot be deleted while it still
    # has a quota share, so the share must be gone before the queue teardown starts.
    _poll_until(lambda: _quota_share_gone(batch, arn), bool, timeout_s=300.0, interval_s=2.0)


def _quota_share_gone(batch, arn: str) -> bool:
    """A share reads DELETED or is refused as unknown (ClientException) once it is gone."""
    try:
        return batch.describe_quota_share(quotaShareArn=arn).get("status") == "DELETED"
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClientException":
            raise
        return True


def _disable_and_delete_job_queue(ctx, jq_name: str) -> None:
    batch = ctx.client("batch")
    if not batch.describe_job_queues(jobQueues=[jq_name])["jobQueues"]:
        return
    batch.update_job_queue(jobQueue=jq_name, state="DISABLED")
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[jq_name])["jobQueues"][0],
        lambda jq: jq["status"] == "VALID" and jq["state"] == "DISABLED",
        timeout_s=180.0,
    )
    _retry(lambda: batch.delete_job_queue(jobQueue=jq_name))
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[jq_name])["jobQueues"],
        lambda queues: queues == [],
        timeout_s=300.0,
    )


def _disable_and_delete_service_environment(ctx, se_name: str) -> None:
    batch = ctx.client("batch")
    if not batch.describe_service_environments(serviceEnvironments=[se_name])["serviceEnvironments"]:
        return
    batch.update_service_environment(serviceEnvironment=se_name, state="DISABLED")
    _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[se_name])["serviceEnvironments"][0],
        lambda se: se["status"] == "VALID" and se["state"] == "DISABLED",
        timeout_s=60.0,
    )
    _retry(lambda: batch.delete_service_environment(serviceEnvironment=se_name))


def _retry(fn, timeout_s: float = 300.0, interval_s: float = 2.0):
    """Retry a teardown delete Batch refuses (ClientException) while a dependent is still deleting."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClientException" or time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


def _delete_scheduling_policy(ctx, arn: str) -> None:
    """Delete the policy, retrying while Batch still reports the (asynchronously deleting) queue."""
    batch = ctx.client("batch")
    _retry(lambda: batch.delete_scheduling_policy(arn=arn))


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
