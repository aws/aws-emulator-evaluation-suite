"""terminate-service-jobs-bulk-without-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "terminate-service-jobs-bulk-without-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["batch", "iam", "s3", "sts"]

_MANAGED_TAGS = {"sim2real-check": CHECK}


@tags("axis:rejection", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TerminateServiceJobs from a role with no policies fails with AccessDeniedException
    for every requested job; a permitted principal then terminates the same job (FAILED)."""
    batch = ctx.client("batch")
    role_arn = _create_sagemaker_role(ctx)
    bucket = _create_output_bucket(ctx)
    queue_arn = _create_sagemaker_queue(ctx)

    job_name = ctx.unique_name("sim2real-batch-bulkdeny-sj-")
    payload = _service_job_payload(ctx, job_name, role_arn, bucket)
    job_id = batch.submit_service_job(
        jobName=job_name,
        jobQueue=queue_arn,
        serviceJobType="SAGEMAKER_TRAINING",
        serviceRequestPayload=payload,
        schedulingPriority=1,
        shareIdentifier="default",
    )["jobId"]
    ctx.on_cleanup(lambda: batch.terminate_service_jobs(jobs=[job_id], reason="sim2real: cleanup"))

    restricted_batch, restricted_arn = _restricted_batch_client(ctx)

    # Break exactly one thing: call the bulk operation with a principal that holds no
    # batch permissions at all.
    error = _error(
        lambda: restricted_batch.terminate_service_jobs(
            jobs=[job_id], reason="sim2real: unauthorized bulk attempt"
        )
    )
    code, message = error.get("Code"), error.get("Message")
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    job_arn = f"arn:aws:batch:{ctx.region}:{ctx.account}:service-job/{job_id}"
    expected = (
        f"User: {restricted_arn} is not authorized to perform: batch:TerminateServiceJob on resource: "
        f"{job_arn} because no identity-based policy allows the batch:TerminateServiceJob action"
    )
    assert message == expected, f"expected the exact AccessDenied message {expected!r}, got {message!r}"

    # Effect absent: the job was not terminated by the denied attempt.
    untouched = batch.describe_service_job(jobId=job_id)
    assert untouched["status"] != "FAILED", f"expected status != FAILED, got {untouched['status']!r}"
    assert untouched.get("isTerminated", False) is False, (
        f"expected isTerminated False (or absent) after the denied attempt, got {untouched.get('isTerminated')!r}"
    )

    # Positive control: the same bulk call from the unrestricted caller succeeds.
    result = batch.terminate_service_jobs(jobs=[job_id], reason="sim2real: authorized bulk termination")
    assert result["errors"] == [], f"expected no per-job errors, got {result['errors']!r}"
    assert result["successful"] == [job_id], (
        f"expected successful == [{job_id!r}], got {result['successful']!r}"
    )
    final = _poll_until(
        lambda: batch.describe_service_job(jobId=job_id),
        lambda job: job["status"] == "FAILED",
        timeout_s=180,
    )
    assert final["isTerminated"] is True, f"expected isTerminated True, got {final['isTerminated']!r}"


# ===== helpers =====

def _undo(fn, retry_s: float = 0.0) -> None:
    """Run a teardown step; "does not exist" means done. A ClientException for a
    resource still in use is retried every 2s for retry_s; anything else raises."""
    deadline = time.monotonic() + retry_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            e = err.response["Error"]
            if e["Code"] == "NoSuchEntity" or (
                e["Code"] == "ClientException" and "does not exist" in e.get("Message", "")
            ):
                return
            if e["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_sagemaker_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-bulkdeny-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        _undo(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
        _undo(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"],
        lambda policies: any(p["PolicyArn"] == policy_arn for p in policies),
        timeout_s=30,
        interval_s=2,
    )
    return role_arn


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-batch-bulkdeny-out-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]},
    )

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_sagemaker_queue(ctx) -> str:
    batch = ctx.client("batch")

    policy_name = ctx.unique_name("sim2real-batch-bulkdeny-schedpol-")
    policy_arn = batch.create_scheduling_policy(
        name=policy_name,
        fairsharePolicy={"computeReservation": 0, "shareDecaySeconds": 0, "shareDistribution": []},
        tags=_MANAGED_TAGS,
    )["arn"]
    ctx.on_cleanup(lambda: _undo(lambda: batch.delete_scheduling_policy(arn=policy_arn), retry_s=90))

    env_name = ctx.unique_name("sim2real-batch-bulkdeny-se-")
    env_arn = batch.create_service_environment(
        serviceEnvironmentName=env_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "NUM_INSTANCES", "maxCapacity": 4}],
        state="ENABLED",
        tags=_MANAGED_TAGS,
    )["serviceEnvironmentArn"]

    def _cleanup_env():
        _undo(lambda: batch.update_service_environment(serviceEnvironment=env_arn, state="DISABLED"))
        _poll_until(
            lambda: batch.describe_service_environments(serviceEnvironments=[env_arn])["serviceEnvironments"][0]["status"],
            lambda s: s in ("VALID", "INVALID"),
            timeout_s=90,
        )
        _undo(lambda: batch.delete_service_environment(serviceEnvironment=env_arn), retry_s=90)

    ctx.on_cleanup(_cleanup_env)
    _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[env_arn])["serviceEnvironments"][0]["status"],
        lambda s: s in ("VALID", "INVALID"),
        timeout_s=90,
    )

    queue_name = ctx.unique_name("sim2real-batch-bulkdeny-sq-")
    queue_arn = batch.create_job_queue(
        jobQueueName=queue_name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        state="ENABLED",
        schedulingPolicyArn=policy_arn,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": env_arn}],
        tags=_MANAGED_TAGS,
    )["jobQueueArn"]

    def _cleanup_queue():
        _undo(lambda: batch.update_job_queue(jobQueue=queue_arn, state="DISABLED"))
        _poll_until(
            lambda: batch.describe_job_queues(jobQueues=[queue_arn])["jobQueues"][0]["status"],
            lambda s: s in ("VALID", "INVALID"),
            timeout_s=90,
        )
        _undo(lambda: batch.delete_job_queue(jobQueue=queue_arn), retry_s=90)

    ctx.on_cleanup(_cleanup_queue)
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[queue_arn])["jobQueues"][0]["status"],
        lambda s: s in ("VALID", "INVALID"),
        timeout_s=90,
    )
    return queue_arn


def _service_job_payload(ctx, job_name: str, role_arn: str, bucket: str, max_runtime: int = 300) -> str:
    payload = {
        "TrainingJobName": job_name,
        "RoleArn": role_arn,
        "AlgorithmSpecification": {
            "TrainingInputMode": "File",
            "TrainingImage": f"123456789012.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-training:2.0.0-cpu-py310",
            "ContainerEntrypoint": ["echo", "hello-world"],
        },
        "ResourceConfig": {"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 1},
        "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/output"},
        "StoppingCondition": {"MaxRuntimeInSeconds": max_runtime},
    }
    return json.dumps(payload)


def _restricted_batch_client(ctx):
    """Assume a policy-less role trusted by this account; return its batch client and role ARN.

    Every action, including batch:TerminateServiceJob, is implicitly denied for it."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = ctx.account
    name = ctx.unique_name("sim2real-batch-bulkdeny-noperm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )
    role_arn = resp["Role"]["Arn"]

    def _cleanup():
        _undo(lambda: iam.delete_role(RoleName=name))

    ctx.on_cleanup(_cleanup)

    def _try_assume():
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-batch-bulkdeny-noperm")
        except ClientError:
            return None

    assumed = _poll_until(
        _try_assume,
        lambda resp: resp is not None,
        timeout_s=30,
        interval_s=3,
    )
    creds = assumed["Credentials"]
    client = ctx.client(
        "batch",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return client, assumed["AssumedRoleUser"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
