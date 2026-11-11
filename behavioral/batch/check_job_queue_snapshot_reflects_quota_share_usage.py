"""job-queue-snapshot-reflects-quota-share-usage."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "job-queue-snapshot-reflects-quota-share-usage"
GROUP = "data-plane"
SERVICES = ["batch"]

_NON_TERMINAL = {"SUBMITTED", "PENDING", "RUNNABLE", "SCHEDULED", "STARTING", "RUNNING"}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetJobQueueSnapshot reports 0 usage for a quota share before any job, usage above 0 for
    it while its service job runs, and 0 for an idle second share and every other share: the
    snapshot tracks live consumption per share by name."""
    batch = ctx.client("batch")
    role_arn = _create_sagemaker_role(ctx)
    bucket = _create_output_bucket(ctx)
    senv_name = _create_service_environment(ctx)
    sp_arn = _create_scheduling_policy(ctx)
    jq_name = _create_job_queue(ctx, senv_name, sp_arn)
    qs_name, qs_arn = _create_quota_share(ctx, jq_name, max_capacity=1)
    # A second, idle quota share on the same queue -- nothing is ever submitted against it, so
    # any usage the target attributes to it (rather than to qs_name) is a misattribution.
    idle_qs_name, _idle_qs_arn = _create_quota_share(ctx, jq_name, max_capacity=1)

    before = batch.get_job_queue_snapshot(jobQueue=jq_name)
    assert _capacity_for_share(before, qs_name) == 0.0, "expected zero usage before any job is submitted"

    training_job_name = ctx.unique_name("sim2real-batch-snap-tj-")
    payload = {
        "TrainingJobName": training_job_name,
        "RoleArn": role_arn,
        "AlgorithmSpecification": {
            "TrainingInputMode": "File",
            "TrainingImage": f"763104351884.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-training:2.0.0-cpu-py310",
            "ContainerEntrypoint": ["sleep", "120"],
        },
        "ResourceConfig": {"InstanceType": "ml.m6i.large", "InstanceCount": 1, "VolumeSizeInGB": 1},
        "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/output"},
        "StoppingCondition": {"MaxRuntimeInSeconds": 180},
    }

    job_name = ctx.unique_name("sim2real-batch-snap-sj-")
    submitted = _submit_service_job_with_retry(
        batch,
        jobName=job_name,
        jobQueue=jq_name,
        serviceJobType="SAGEMAKER_TRAINING",
        serviceRequestPayload=json.dumps(payload),
        quotaShareName=qs_name,
        schedulingPriority=5,
    )
    job_id = submitted["jobId"]
    ctx.on_cleanup(lambda: _terminate_best_effort(batch, job_id))

    during = _wait_for(
        lambda: batch.get_job_queue_snapshot(jobQueue=jq_name),
        lambda snap: _capacity_for_share(snap, qs_name) > 0.0,
        timeout_s=420,
        interval_s=5,
    )
    during_usage = _capacity_for_share(during, qs_name)
    assert during_usage > 0.0, "snapshot never reflected the running job's quota consumption"
    assert during_usage != _capacity_for_share(before, qs_name), (
        "snapshot usage did not change between before/during -- looks cached/static"
    )
    idle_usage = _capacity_for_share(during, idle_qs_name)
    assert idle_usage == 0.0, (
        f"job's usage was misattributed to the idle quota share {idle_qs_name!r}: {idle_usage}"
    )
    # No other quota share on this queue should be charged for this job's usage.
    other_shares_charged = [
        entry["quotaShareName"]
        for entry in (during.get("queueUtilization") or {}).get("quotaShareUtilization", {}).get(
            "topCapacityUtilization", []
        )
        if entry["quotaShareName"] != qs_name and _sum_usage(entry) > 0.0
    ]
    assert other_shares_charged == [], f"usage misattributed to other quota shares: {other_shares_charged}"


def _sum_usage(entry) -> float:
    return sum(float(u.get("quantity", 0)) for u in entry.get("capacityUsage", []))


def _capacity_for_share(snapshot, qs_name: str) -> float:
    util = snapshot.get("queueUtilization") or {}
    qsu = util.get("quotaShareUtilization") or {}
    total = 0.0
    for entry in qsu.get("topCapacityUtilization", []):
        if entry.get("quotaShareName") == qs_name:
            total += _sum_usage(entry)
    return total


def _wait_for(probe, predicate, *, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _terminate_best_effort(batch, job_id):
    batch.terminate_service_job(jobId=job_id, reason="sim2real-behavioral-cleanup")


def _create_service_environment(ctx, capacity_unit="ml.m6i.large", max_capacity=10):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-senv-")
    batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": capacity_unit, "maxCapacity": max_capacity}],
        tags={"env": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: _delete_service_environment(ctx, name))
    _wait_for(
        lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0],
        lambda se: se["status"] == "VALID",
    )
    return name


def _delete_service_environment(ctx, name):
    batch = ctx.client("batch")
    try:
        batch.update_service_environment(serviceEnvironment=name, state="DISABLED")
        _wait_for(
            lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0],
            lambda se: se["status"] == "VALID" and se["state"] == "DISABLED",
            timeout_s=60,
        )
        _retry_delete(lambda: batch.delete_service_environment(serviceEnvironment=name))
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


def _create_scheduling_policy(ctx):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")
    created = batch.create_scheduling_policy(
        name=name,
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags={"env": "sim2real-behav"},
    )
    arn = created["arn"]
    ctx.on_cleanup(lambda: _delete_scheduling_policy_best_effort(ctx, arn))
    return arn


def _delete_scheduling_policy_best_effort(ctx, arn):
    batch = ctx.client("batch")
    _retry_delete(lambda: batch.delete_scheduling_policy(arn=arn))


def _create_job_queue(ctx, service_env_name, scheduling_policy_arn):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-jq-")
    batch.create_job_queue(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": service_env_name}],
        schedulingPolicyArn=scheduling_policy_arn,
        tags={"env": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: _delete_job_queue(ctx, name))
    _wait_for(
        lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"][0],
        lambda jq: jq["status"] == "VALID",
    )
    return name


def _delete_job_queue(ctx, name):
    batch = ctx.client("batch")
    try:
        batch.update_job_queue(jobQueue=name, state="DISABLED")
        _wait_for(
            lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"][0],
            lambda jq: jq["status"] == "VALID" and jq["state"] == "DISABLED",
            timeout_s=60,
        )
        _retry_delete(lambda: batch.delete_job_queue(jobQueue=name))
        _wait_jq_gone(batch, name)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


def _create_quota_share(ctx, jq_name, max_capacity=1):
    batch = ctx.client("batch")
    qs_name = ctx.unique_name("sim2real-batch-qs-")
    created = batch.create_quota_share(
        quotaShareName=qs_name,
        jobQueue=jq_name,
        capacityLimits=[{"capacityUnit": "ml.m6i.large", "maxCapacity": max_capacity}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        tags={"env": "sim2real-behav"},
    )
    qs_arn = created["quotaShareArn"]
    ctx.on_cleanup(lambda: _delete_quota_share_best_effort(ctx, qs_arn))
    _wait_for(
        lambda: batch.describe_quota_share(quotaShareArn=qs_arn),
        lambda d: d["status"] == "VALID",
    )
    return qs_name, qs_arn


def _delete_quota_share_best_effort(ctx, arn):
    batch = ctx.client("batch")
    try:
        batch.update_quota_share(quotaShareArn=arn, state="DISABLED")
        _wait_for(
            lambda: batch.describe_quota_share(quotaShareArn=arn),
            lambda d: d["status"] == "VALID" and d["state"] == "DISABLED",
            timeout_s=60,
        )
        _retry_delete(lambda: batch.delete_quota_share(quotaShareArn=arn))
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ClientException"
            and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
        ):
            raise


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-snap-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    created = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = created["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess")

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    # No unconditional sleep for IAM's cross-service propagation delay: submit_service_job is
    # called through _submit_service_job_with_retry below, which already retries on the
    # ClientException a not-yet-propagated role produces, bounded by its own deadline.
    return role_arn


def _create_output_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-batch-snap-out-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup():
        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            for obj in objs:
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


def _submit_service_job_with_retry(batch, *, attempts=6, delay_s=10.0, **kwargs):
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
