"""submit-service-job-missing-quota-share-name-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "submit-service-job-missing-quota-share-name-rejected"
GROUP = "e2e"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SubmitServiceJob omitting quotaShareName on a quota-share queue fails with ClientException.

    No job is created; the same payload with quotaShareName is accepted on that queue."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    batch = ctx.client("batch")
    role_arn = _create_sagemaker_role(ctx)
    bucket = _create_output_bucket(ctx)
    senv_name = _create_service_environment(ctx, teardown_deadline)
    sp_arn = _create_scheduling_policy(ctx, teardown_deadline)
    jq_name = _create_job_queue(ctx, senv_name, sp_arn, teardown_deadline)
    qs_name, qs_arn = _create_quota_share(ctx, jq_name)

    payload = {
        "TrainingJobName": ctx.unique_name("sim2real-batch-neg-tj-"),
        "RoleArn": role_arn,
        "AlgorithmSpecification": {
            "TrainingInputMode": "File",
            "TrainingImage": f"123456789012.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-training:2.0.0-cpu-py310",
            "ContainerEntrypoint": ["echo", "should never run"],
        },
        "ResourceConfig": {"InstanceType": "ml.m6i.large", "InstanceCount": 1, "VolumeSizeInGB": 1},
        "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/output"},
        "StoppingCondition": {"MaxRuntimeInSeconds": 60},
    }

    rejected_job_name = ctx.unique_name("sim2real-batch-neg-sj-")
    error = _error(
        lambda: batch.submit_service_job(
            jobName=rejected_job_name,
            jobQueue=jq_name,
            serviceJobType="SAGEMAKER_TRAINING",
            serviceRequestPayload=json.dumps(payload),
            schedulingPriority=5,
            # quotaShareName intentionally omitted -- required for a quota-share-policy queue.
        )
    )
    code, message = error.get("Code"), error.get("Message")
    assert code == "ClientException", f"expected ClientException for a missing quotaShareName, got {code!r}"
    assert message == (
        "Job without quotaShareName cannot be submitted to a job queue with quota share scheduling policy."
    ), f"expected the exact missing-quotaShareName message, got {message!r}"

    summaries = _list_all_service_jobs(batch, jq_name)
    names = [s["jobName"] for s in summaries]
    assert rejected_job_name not in names, f"rejected submission must not have created a job, found in {names}"

    # Positive control: the same payload, on the same queue, succeeds once quotaShareName is set.
    accepted_job_name = ctx.unique_name("sim2real-batch-pos-sj-")
    submitted = _submit_service_job_with_retry(
        batch,
        jobName=accepted_job_name,
        jobQueue=jq_name,
        serviceJobType="SAGEMAKER_TRAINING",
        serviceRequestPayload=json.dumps(payload),
        quotaShareName=qs_name,
        schedulingPriority=5,
    )
    job_id = submitted["jobId"]
    ctx.on_cleanup(lambda: _terminate_best_effort(batch, job_id))

    described = batch.describe_service_job(jobId=job_id)
    assert described["jobName"] == accepted_job_name, (
        f"expected jobName {accepted_job_name!r}, got {described['jobName']!r}"
    )
    assert described["quotaShareName"] == qs_name, (
        f"expected quotaShareName {qs_name!r}, got {described.get('quotaShareName')!r}"
    )


def _list_all_service_jobs(batch, jq_name):
    out = []
    kwargs = {"jobQueue": jq_name}
    while True:
        resp = batch.list_service_jobs(**kwargs)
        out.extend(resp.get("jobSummaryList", []))
        token = resp.get("nextToken")
        if not token:
            return out
        kwargs["nextToken"] = token


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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


def _create_service_environment(ctx, teardown_deadline, capacity_unit="ml.m6i.large", max_capacity=10):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-senv-")
    batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": capacity_unit, "maxCapacity": max_capacity}],
        tags={"sim2real": "behav"},
    )
    ctx.on_cleanup(lambda: _delete_service_environment(ctx, name, teardown_deadline))
    _wait_for(
        lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0],
        lambda se: se["status"] == "VALID",
    )
    return name


def _delete_service_environment(ctx, name, teardown_deadline):
    batch = ctx.client("batch")
    try:
        batch.update_service_environment(serviceEnvironment=name, state="DISABLED")
        _wait_for(
            lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0],
            lambda se: se["status"] == "VALID" and se["state"] == "DISABLED",
            timeout_s=60,
        )
        _retry_in_use(ctx, lambda: batch.delete_service_environment(serviceEnvironment=name), teardown_deadline)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


def _create_scheduling_policy(ctx, teardown_deadline):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")
    created = batch.create_scheduling_policy(
        name=name,
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags={"sim2real": "behav"},
    )
    arn = created["arn"]
    ctx.on_cleanup(lambda: _delete_scheduling_policy_best_effort(ctx, arn, teardown_deadline))
    return arn


def _delete_scheduling_policy_best_effort(ctx, arn, teardown_deadline):
    batch = ctx.client("batch")
    _retry_in_use(ctx, lambda: batch.delete_scheduling_policy(arn=arn), teardown_deadline)


def _create_job_queue(ctx, service_env_name, scheduling_policy_arn, teardown_deadline):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-jq-")
    batch.create_job_queue(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": service_env_name}],
        schedulingPolicyArn=scheduling_policy_arn,
        tags={"sim2real": "behav"},
    )
    ctx.on_cleanup(lambda: _delete_job_queue(ctx, name, teardown_deadline))
    _wait_for(
        lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"][0],
        lambda jq: jq["status"] == "VALID",
    )
    return name


def _delete_job_queue(ctx, name, teardown_deadline):
    batch = ctx.client("batch")
    try:
        batch.update_job_queue(jobQueue=name, state="DISABLED")
        _wait_for(
            lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"][0],
            lambda jq: jq["status"] == "VALID" and jq["state"] == "DISABLED",
            timeout_s=60,
        )
        _retry_in_use(ctx, lambda: batch.delete_job_queue(jobQueue=name), teardown_deadline)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


def _create_quota_share(ctx, jq_name, max_capacity=5):
    batch = ctx.client("batch")
    qs_name = ctx.unique_name("sim2real-batch-qs-")
    created = batch.create_quota_share(
        quotaShareName=qs_name,
        jobQueue=jq_name,
        capacityLimits=[{"capacityUnit": "ml.m6i.large", "maxCapacity": max_capacity}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        tags={"sim2real": "behav"},
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
        batch.delete_quota_share(quotaShareArn=arn)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ClientException"
            and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
        ):
            raise


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-neg-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    created = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "behav"}],
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
    # IAM propagation exposes no condition to poll; the bounded retry in
    # _submit_service_job_with_retry (below) is what actually absorbs the lag for the
    # call that depends on the role. The rejected submission's ClientException is a
    # validation error independent of role readiness, so it needs no wait at all.
    return role_arn


def _create_output_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-batch-neg-out-").lower()
    # "us-east-1" here is S3's own API quirk, not a pinned region: CreateBucket rejects an
    # explicit LocationConstraint of us-east-1 and requires omitting it instead.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "behav"}]})

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
