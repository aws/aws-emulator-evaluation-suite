"""e2e-service-job-quota-share-consumption-flow."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-service-job-quota-share-consumption-flow"
GROUP = "e2e"
SERVICES = ["batch"]

_NON_TERMINAL = {"SUBMITTED", "PENDING", "RUNNABLE", "SCHEDULED", "STARTING", "RUNNING"}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A service job on a quota share raises the share's GetJobQueueSnapshot usage from 0 to above 0
    while it runs, leaves the share VALID and ENABLED, ends FAILED when terminated, and its usage then
    returns to 0: the quota is consumed and released by the job."""
    batch = ctx.client("batch")
    role_arn = _create_sagemaker_role(ctx)
    bucket = _create_output_bucket(ctx)
    senv_name = _create_service_environment(ctx)
    sp_arn = _create_scheduling_policy(ctx)
    jq_name = _create_job_queue(ctx, senv_name, sp_arn)
    qs_name, qs_arn = _create_quota_share(ctx, jq_name, max_capacity=2)

    baseline = batch.get_job_queue_snapshot(jobQueue=jq_name)
    assert _capacity_for_share(baseline, qs_name) == 0.0, "expected zero usage before any job is submitted"

    training_job_name = ctx.unique_name("sim2real-batch-e2e-tj-")
    payload = {
        "TrainingJobName": training_job_name,
        "RoleArn": role_arn,
        "AlgorithmSpecification": {
            "TrainingInputMode": "File",
            "TrainingImage": f"763104351884.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-training:2.0.0-cpu-py310",
            "ContainerEntrypoint": ["sleep", "180"],
        },
        "ResourceConfig": {"InstanceType": "ml.m6i.large", "InstanceCount": 1, "VolumeSizeInGB": 1},
        "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/output"},
        "StoppingCondition": {"MaxRuntimeInSeconds": 240},
    }

    job_name = ctx.unique_name("sim2real-batch-e2e-sj-")
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

    # Consumption must show up as the job runs -- poll until the quota share's usage is non-zero.
    _wait_for(
        lambda: batch.get_job_queue_snapshot(jobQueue=jq_name),
        lambda snap: _capacity_for_share(snap, qs_name) > 0.0,
        timeout_s=420,
        interval_s=5,
    )

    mid_desc = batch.describe_quota_share(quotaShareArn=qs_arn)
    assert mid_desc["status"] == "VALID" and mid_desc["state"] == "ENABLED", (
        "quota share's own configuration state must be untouched by job consumption"
    )

    batch.terminate_service_job(jobId=job_id, reason="sim2real-behavioral-terminate")

    final = _wait_for(
        lambda: batch.describe_service_job(jobId=job_id),
        lambda d: d["status"] not in _NON_TERMINAL,
        timeout_s=300,
        interval_s=5,
    )
    assert final["status"] == "FAILED", f"expected terminated job to end FAILED, got {final['status']!r}"

    # The quota consumed by the terminated job must be released back to zero.
    _wait_for(
        lambda: batch.get_job_queue_snapshot(jobQueue=jq_name),
        lambda snap: _capacity_for_share(snap, qs_name) == 0.0,
        timeout_s=120,
        interval_s=5,
    )


def _capacity_for_share(snapshot, qs_name: str) -> float:
    util = snapshot.get("queueUtilization") or {}
    qsu = util.get("quotaShareUtilization") or {}
    total = 0.0
    for entry in qsu.get("topCapacityUtilization", []):
        if entry.get("quotaShareName") == qs_name:
            for usage in entry.get("capacityUsage", []):
                total += float(usage.get("quantity", 0))
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


def _create_service_environment(ctx, capacity_unit="ml.m6i.large", max_capacity=10):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-senv-")
    batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": capacity_unit, "maxCapacity": max_capacity}],
        tags={"sim2real": "true"},
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
        tags={"sim2real": "true"},
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
        tags={"sim2real": "true"},
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


def _create_quota_share(ctx, jq_name, max_capacity=2):
    batch = ctx.client("batch")
    qs_name = ctx.unique_name("sim2real-batch-qs-")
    created = batch.create_quota_share(
        quotaShareName=qs_name,
        jobQueue=jq_name,
        capacityLimits=[{"capacityUnit": "ml.m6i.large", "maxCapacity": max_capacity}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        tags={"sim2real": "true"},
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
    role_name = ctx.unique_name("sim2real-batch-e2e-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    created = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
    # IAM role propagation to SageMaker has no independent probe; the bounded retry in
    # _submit_service_job_with_retry (the only caller that depends on the role being assumable)
    # is what actually waits for it, catching SubmitServiceJob's sole client-error shape.
    return role_arn


def _create_output_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-batch-e2e-out-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})

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
