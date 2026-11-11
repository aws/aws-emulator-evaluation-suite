"""service-job-lifecycle-transitions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-job-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SubmitServiceJob produces a job that progresses to SUCCEEDED via DescribeServiceJob polls."""
    batch = ctx.client("batch")
    queue = _create_quota_managed_job_queue(ctx)
    role_arn = _create_sagemaker_role(ctx)
    bucket = _create_output_bucket(ctx)
    quota_share_name = _create_quota_share(ctx, queue["jobQueueName"])
    job_id = _submit_service_job(ctx, queue["jobQueueArn"], role_arn, bucket, quota_share_name, max_runtime=60)

    # Immediately after submission the job must be in a non-terminal state.
    initial = batch.describe_service_job(jobId=job_id)
    assert initial["status"] in {
        "SUBMITTED",
        "PENDING",
        "RUNNABLE",
        "SCHEDULED",
        "STARTING",
        "RUNNING",
    }

    final = _poll_service_job_terminal(ctx, job_id, timeout_s=900)
    assert final["status"] == "SUCCEEDED", f"job ended with status {final['status']}: {final.get('statusReason')}"
    assert "startedAt" in final and "stoppedAt" in final
    assert final["stoppedAt"] >= final["startedAt"]


# ===== helpers =====


def _delete_retrying(delete, budget_s):
    """Run a Batch delete; a resource that does not exist is done. Batch refuses a delete with
    ClientException while a dependent resource is still releasing, so that is retried every 2 s
    until budget_s, then raised."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            delete()
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                return
            if err["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _wait_service_environment_valid(ctx, arn, timeout_s=180):
    batch = ctx.client("batch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = batch.describe_service_environments(serviceEnvironments=[arn])
        envs = resp.get("serviceEnvironments", [])
        if envs:
            status = envs[0]["status"]
            if status == "VALID":
                return envs[0]
            if status == "INVALID":
                raise AssertionError(f"service environment became INVALID: {envs[0]}")
        time.sleep(3)
    raise AssertionError("service environment did not reach VALID in time")


def _wait_job_queue_valid(ctx, arn, timeout_s=180):
    batch = ctx.client("batch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = batch.describe_job_queues(jobQueues=[arn])
        queues = resp.get("jobQueues", [])
        if queues:
            status = queues[0]["status"]
            if status == "VALID":
                return queues[0]
            if status == "INVALID":
                raise AssertionError(f"job queue became INVALID: {queues[0]}")
        time.sleep(3)
    raise AssertionError("job queue did not reach VALID in time")


def _safe_delete_scheduling_policy(ctx, arn):
    batch = ctx.client("batch")
    _delete_retrying(lambda: batch.delete_scheduling_policy(arn=arn), 60)


def _create_quota_managed_job_queue(ctx):
    batch = ctx.client("batch")
    sp_name = ctx.unique_name("sim2real-batch-sp-")
    sp = batch.create_scheduling_policy(
        name=sp_name,
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
    )
    sp_arn = sp["arn"]
    ctx.on_cleanup(lambda: _safe_delete_scheduling_policy(ctx, sp_arn))

    se_name = ctx.unique_name("sim2real-batch-se-")
    se = batch.create_service_environment(
        serviceEnvironmentName=se_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"maxCapacity": 2, "capacityUnit": "ml.c5.xlarge"}],
    )
    se_arn = se["serviceEnvironmentArn"]

    def _cleanup_se():
        try:
            batch.update_service_environment(serviceEnvironment=se_arn, state="DISABLED")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
        _delete_retrying(lambda: batch.delete_service_environment(serviceEnvironment=se_arn), 90)

    ctx.on_cleanup(_cleanup_se)
    _wait_service_environment_valid(ctx, se_arn)

    jq_name = ctx.unique_name("sim2real-batch-jq-")
    jq = batch.create_job_queue(
        jobQueueName=jq_name,
        priority=1,
        jobQueueType="SAGEMAKER_TRAINING",
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": se_arn}],
        schedulingPolicyArn=sp_arn,
    )
    jq_arn = jq["jobQueueArn"]

    def _cleanup_jq():
        try:
            batch.update_job_queue(jobQueue=jq_arn, state="DISABLED")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
        _delete_retrying(lambda: batch.delete_job_queue(jobQueue=jq_arn), 90)

    ctx.on_cleanup(_cleanup_jq)
    _wait_job_queue_valid(ctx, jq_arn)
    return {
        "jobQueueArn": jq_arn,
        "jobQueueName": jq_name,
        "serviceEnvironmentArn": se_arn,
        "schedulingPolicyArn": sp_arn,
    }


def _wait_role_assumable(ctx, role_name, policy_arn, timeout_s=60):
    """Bounded poll for IAM's own read path to reflect the role and its policy attachment,
    rather than an unconditional sleep guessing at propagation time."""
    iam = ctx.client("iam")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
            if any(p["PolicyArn"] == policy_arn for p in attached):
                return
        except ClientError:
            pass
        time.sleep(3)
    raise AssertionError(f"role {role_name} policy attachment did not become visible within {timeout_s}s")


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-sm-role-")
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = role["Role"]["Arn"]
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
    _wait_role_assumable(ctx, role_name, policy_arn)
    return role_arn


def _create_output_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-batch-smout-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup():
        try:
            resp = s3.list_objects_v2(Bucket=bucket)
            for obj in resp.get("Contents", []):
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


def _create_quota_share(ctx, job_queue_name, max_capacity=2):
    # Real AWS Batch requires a SAGEMAKER_TRAINING service job submitted to a job queue
    # bound to a quota-management scheduling policy to carry a quotaShareName (and a
    # schedulingPriority); without one, SubmitServiceJob is rejected outright with
    # ClientException before a job is ever created.
    batch = ctx.client("batch")
    qs_name = ctx.unique_name("sim2real-batch-qs-")
    qs = batch.create_quota_share(
        quotaShareName=qs_name,
        jobQueue=job_queue_name,
        capacityLimits=[{"maxCapacity": max_capacity, "capacityUnit": "ml.c5.xlarge"}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
    )
    qs_arn = qs["quotaShareArn"]
    ctx.on_cleanup(lambda: _safe_delete_quota_share(ctx, qs_arn))
    _wait_quota_share_valid(ctx, qs_arn)
    return qs_name


def _wait_quota_share_valid(ctx, arn, timeout_s=180):
    batch = ctx.client("batch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = batch.describe_quota_share(quotaShareArn=arn)
        status = desc["status"]
        if status == "VALID":
            return desc
        if status == "INVALID":
            raise AssertionError(f"quota share became INVALID: {desc}")
        time.sleep(3)
    raise AssertionError("quota share did not reach VALID in time")


def _safe_delete_quota_share(ctx, arn):
    batch = ctx.client("batch")
    try:
        batch.update_quota_share(quotaShareArn=arn, state="DISABLED")
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ClientException"
            and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
        ):
            raise
    _delete_retrying(lambda: batch.delete_quota_share(quotaShareArn=arn), 90)


def _submit_service_job(ctx, queue_arn, role_arn, bucket, quota_share_name, max_runtime=60):
    batch = ctx.client("batch")
    payload = {
        "TrainingJobName": ctx.unique_name("sim2real-batch-tj-")[:63],
        "RoleArn": role_arn,
        "AlgorithmSpecification": {
            "TrainingInputMode": "File",
            "TrainingImage": f"763104351884.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-training:2.0.0-cpu-py310",
            "ContainerEntrypoint": ["echo", "hello world"],
        },
        "ResourceConfig": {"InstanceType": "ml.c5.xlarge", "InstanceCount": 1, "VolumeSizeInGB": 1},
        "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/output"},
        "StoppingCondition": {"MaxRuntimeInSeconds": max_runtime},
    }
    resp = batch.submit_service_job(
        jobQueue=queue_arn,
        jobName=ctx.unique_name("sim2real-batch-sj-"),
        serviceJobType="SAGEMAKER_TRAINING",
        serviceRequestPayload=json.dumps(payload),
        quotaShareName=quota_share_name,
        schedulingPriority=1,
        retryStrategy={"attempts": 1},
        timeoutConfig={"attemptDurationSeconds": max_runtime + 120},
    )
    job_id = resp["jobId"]
    ctx.on_cleanup(lambda: _safe_terminate_service_job(ctx, job_id))
    return job_id


def _safe_terminate_service_job(ctx, job_id):
    batch = ctx.client("batch")
    batch.terminate_service_job(jobId=job_id, reason="check cleanup")


def _poll_service_job_terminal(ctx, job_id, timeout_s=900):
    batch = ctx.client("batch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = batch.describe_service_job(jobId=job_id)
        last = resp
        if resp["status"] in {"SUCCEEDED", "FAILED"}:
            return resp
        time.sleep(2)
    raise AssertionError(f"service job did not reach a terminal state, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
