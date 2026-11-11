"""service-job-lifecycle-submit-to-terminal."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-job-lifecycle-submit-to-terminal"
GROUP = "state-machine"
SERVICES = ["batch"]

_NON_TERMINAL = {"SUBMITTED", "PENDING", "RUNNABLE", "SCHEDULED", "STARTING", "RUNNING"}
_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK}


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A new SAGEMAKER_TRAINING service job starts non-terminal with isTerminated false, and after
    TerminateServiceJob ends FAILED with isTerminated true and a statusReason holding the
    terminate reason."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    batch = ctx.client("batch")
    role_arn = _create_sagemaker_role(ctx)
    bucket = _create_output_bucket(ctx)
    senv_name = _create_service_environment(ctx, teardown_deadline)
    jq_name = _create_job_queue(ctx, senv_name, teardown_deadline)

    training_job_name = ctx.unique_name("sim2real-batch-tj-")
    payload = {
        "TrainingJobName": training_job_name,
        "RoleArn": role_arn,
        "AlgorithmSpecification": {
            "TrainingInputMode": "File",
            "TrainingImage": f"123456789012.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-training:2.0.0-cpu-py310",
            "ContainerEntrypoint": ["echo", "hello world"],
        },
        "ResourceConfig": {"InstanceType": "ml.m6i.large", "InstanceCount": 1, "VolumeSizeInGB": 1},
        "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/output"},
        "StoppingCondition": {"MaxRuntimeInSeconds": 60},
    }

    job_name = ctx.unique_name("sim2real-batch-sj-")
    submitted = _submit_service_job_with_retry(
        batch,
        jobName=job_name,
        jobQueue=jq_name,
        serviceJobType="SAGEMAKER_TRAINING",
        serviceRequestPayload=json.dumps(payload),
    )
    job_id = submitted["jobId"]

    first = batch.describe_service_job(jobId=job_id)
    assert first["status"] in _NON_TERMINAL, f"unexpected initial status {first['status']!r}"
    assert first["serviceJobType"] == "SAGEMAKER_TRAINING", (
        f"expected serviceJobType SAGEMAKER_TRAINING, got {first['serviceJobType']!r}"
    )
    # Real DescribeServiceJob omits isTerminated while a job is not terminated rather than
    # reporting it as False, so a missing key is equivalent to False.
    assert first.get("isTerminated", False) is False, (
        f"expected isTerminated False (or absent) before termination, got {first.get('isTerminated')!r}"
    )

    terminate_reason = "sim2real-behavioral-terminate"
    batch.terminate_service_job(jobId=job_id, reason=terminate_reason)

    final = _wait_for(
        lambda: batch.describe_service_job(jobId=job_id),
        lambda d: d["status"] not in _NON_TERMINAL,
        timeout_s=300,
        interval_s=5,
    )
    assert final["status"] == "FAILED", f"expected terminated service job to end FAILED, got {final['status']!r}"
    assert final["isTerminated"] is True, f"expected isTerminated True after termination, got {final['isTerminated']!r}"
    # Ties the FAILED status to OUR terminate call rather than an unrelated failure
    # (e.g. a role-assumption problem) that would also leave the job in FAILED.
    assert terminate_reason in (final.get("statusReason") or ""), (
        f"expected termination reason {terminate_reason!r} in statusReason, got {final.get('statusReason')!r}"
    )


def _wait_for(probe, predicate, *, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_service_environment(ctx, teardown_deadline, capacity_unit="NUM_INSTANCES", max_capacity=4):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-senv-")
    batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": capacity_unit, "maxCapacity": max_capacity}],
        tags=_MANAGED_TAGS,
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


def _create_job_queue(ctx, service_env_name, teardown_deadline):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-jq-")
    batch.create_job_queue(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": service_env_name}],
        tags=_MANAGED_TAGS,
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


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-sm-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    created = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=_tags_kv(),
    )
    role_arn = created["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
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
    # The attachment landing is an independent-read-observable condition; the residual
    # IAM->SageMaker cross-service propagation lag beyond that is absorbed by
    # _submit_service_job_with_retry's backoff on the actual dependent call.
    _wait_for(
        lambda: iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"],
        lambda policies: any(p["PolicyArn"] == policy_arn for p in policies),
        timeout_s=30,
        interval_s=2,
    )
    return role_arn


def _create_output_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-batch-sagemaker-out-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_kv()})

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
