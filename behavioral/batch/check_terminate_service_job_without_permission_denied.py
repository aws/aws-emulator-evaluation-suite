"""terminate-service-job-without-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "terminate-service-job-without-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TerminateServiceJob from a role with no policies fails with AccessDeniedException.

    The job stays untouched; the same call from a permitted principal terminates it (FAILED)."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    batch = ctx.client("batch")
    service_env = _create_service_environment(ctx, teardown_deadline)
    job_queue = _create_service_job_queue(ctx, service_env["arn"], teardown_deadline)
    quota_share_name = _create_quota_share(ctx, batch, job_queue["name"])
    role_arn = _create_sagemaker_role(ctx)
    bucket = _create_output_bucket(ctx)
    job_id = _submit_service_job(ctx, job_queue["arn"], role_arn, bucket, quota_share_name, priority=5)
    ctx.on_cleanup(lambda: _try_terminate(batch, job_id))

    restricted_batch, restricted_arn = _restricted_batch_client(ctx)

    # Break exactly one thing: attempt the call with a principal that has zero batch
    # permissions granted.
    error = _error(
        lambda: restricted_batch.terminate_service_job(jobId=job_id, reason="sim2real: unauthorized attempt")
    )
    code, message = error.get("Code"), error.get("Message")
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    job_arn = f"arn:aws:batch:{ctx.region}:{ctx.account}:service-job/{job_id}"
    expected = (
        f"User: {restricted_arn} is not authorized to perform: batch:TerminateServiceJob on resource: "
        f"{job_arn} because no identity-based policy allows the batch:TerminateServiceJob action"
    )
    assert message == expected, f"expected the exact AccessDenied message {expected!r}, got {message!r}"

    # Effect absent: the job was not terminated. Real AWS Batch omits `isTerminated`
    # from DescribeServiceJob entirely while the job has never been terminated, rather
    # than reporting it as `false` -- so absence here means untouched.
    untouched = batch.describe_service_job(jobId=job_id)
    assert untouched["status"] != "FAILED", f"expected status != FAILED, got {untouched['status']!r}"
    assert untouched.get("isTerminated", False) is False, (
        f"expected isTerminated False (or absent), got {untouched.get('isTerminated')!r}"
    )

    # Positive control: the properly-permissioned client can terminate the same job.
    batch.terminate_service_job(jobId=job_id, reason="sim2real: authorized termination")
    terminated = _poll_until(
        lambda: batch.describe_service_job(jobId=job_id),
        lambda job: job["status"] == "FAILED",
        timeout_s=180,
        interval_s=5,
        desc="service job reached FAILED after authorized terminate",
    )
    assert terminated["isTerminated"] is True, f"expected isTerminated True, got {terminated['isTerminated']!r}"


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0, desc="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{desc} not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _try_delete(fn):
    fn()
    return True


def _try_terminate(batch, job_id):
    batch.terminate_service_job(jobId=job_id, reason="sim2real: cleanup")


def _create_service_environment(ctx, teardown_deadline):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-se-")
    resp = batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 4}],
        state="ENABLED",
        tags={"sim2real-check": CHECK},
    )
    arn = resp["serviceEnvironmentArn"]

    def _describe():
        return batch.describe_service_environments(serviceEnvironments=[arn])["serviceEnvironments"][0]

    _poll_until(_describe, lambda se: se["status"] in ("VALID", "INVALID"), desc="service environment VALID")

    def _cleanup():
        try:
            batch.update_service_environment(serviceEnvironment=arn, state="DISABLED")
            _poll_until(_describe, lambda se: se["state"] == "DISABLED", timeout_s=60, desc="SE disabled")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
        _poll_until(
            lambda: _try_delete(lambda: _retry_in_use(
                ctx, lambda: batch.delete_service_environment(serviceEnvironment=arn), teardown_deadline)),
            lambda ok: ok,
            timeout_s=90,
            desc="service environment deleted",
        )

    ctx.on_cleanup(_cleanup)
    return {"name": name, "arn": arn}


def _create_service_job_queue(ctx, service_env_arn, teardown_deadline):
    batch = ctx.client("batch")

    # A SAGEMAKER_TRAINING service environment declares capacityLimits, which makes it
    # "Quota Management compatible" -- real AWS Batch then requires the job queue that
    # references it to carry a schedulingPolicyArn (a quota-management scheduling
    # policy); CreateJobQueue is rejected with ClientException otherwise.
    policy_name = ctx.unique_name("sim2real-batch-qsp-")
    policy_arn = batch.create_scheduling_policy(
        name=policy_name,
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags={"sim2real-check": CHECK},
    )["arn"]
    ctx.on_cleanup(lambda: _try_delete(lambda: _retry_in_use(
        ctx, lambda: batch.delete_scheduling_policy(arn=policy_arn), teardown_deadline)))

    name = ctx.unique_name("sim2real-batch-sjq-")
    resp = batch.create_job_queue(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        state="ENABLED",
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": service_env_arn}],
        schedulingPolicyArn=policy_arn,
        tags={"sim2real-check": CHECK},
    )
    arn = resp["jobQueueArn"]

    def _describe():
        return batch.describe_job_queues(jobQueues=[arn])["jobQueues"][0]

    _poll_until(_describe, lambda jq: jq["status"] in ("VALID", "INVALID"), desc="job queue VALID")

    def _cleanup():
        try:
            batch.update_job_queue(jobQueue=arn, state="DISABLED")
            _poll_until(_describe, lambda jq: jq["state"] == "DISABLED", timeout_s=60, desc="JQ disabled")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
        _poll_until(
            lambda: _try_delete(lambda: _retry_in_use(
                ctx, lambda: batch.delete_job_queue(jobQueue=arn), teardown_deadline)),
            lambda ok: ok,
            timeout_s=90,
            desc="job queue deleted",
        )

    ctx.on_cleanup(_cleanup)
    return {"name": name, "arn": arn}


def _create_quota_share(ctx, batch, queue_name, *, max_capacity=4):
    # A quota-management-compatible job queue also requires a quota share bound to it:
    # real AWS Batch rejects SubmitServiceJob with ClientException ("... requires a
    # quotaShareName") without one.
    name = ctx.unique_name("sim2real-batch-qs-")
    resp = batch.create_quota_share(
        quotaShareName=name,
        jobQueue=queue_name,
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": max_capacity}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        tags={"sim2real-check": CHECK},
    )
    arn = resp["quotaShareArn"]

    def _describe():
        return batch.describe_quota_share(quotaShareArn=arn)

    _poll_until(_describe, lambda qs: qs["status"] in ("VALID", "INVALID"), timeout_s=180, desc="quota share VALID")

    def _cleanup():
        try:
            batch.update_quota_share(quotaShareArn=arn, state="DISABLED")
            _poll_until(_describe, lambda qs: qs["status"] in ("VALID", "INVALID"), timeout_s=90, desc="QS settled")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
            ):
                raise
        _poll_until(
            lambda: _try_delete(lambda: batch.delete_quota_share(quotaShareArn=arn)),
            lambda ok: ok,
            timeout_s=90,
            desc="quota share deleted",
        )

    ctx.on_cleanup(_cleanup)
    return name


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-batch-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    arn = resp["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return arn


def _create_output_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-batch-out-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

    def _cleanup():
        try:
            s3.delete_bucket(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return name


def _service_request_payload(ctx, role_arn, bucket, job_name):
    return json.dumps(
        {
            "TrainingJobName": job_name,
            "AlgorithmSpecification": {
                "TrainingImage": (
                    f"763104351884.dkr.ecr.{ctx.region}.amazonaws.com/"
                    "pytorch-training:2.1.0-cpu-py310-ubuntu20.04-sagemaker"
                ),
                "TrainingInputMode": "File",
            },
            "RoleArn": role_arn,
            "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/output"},
            "ResourceConfig": {"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 1},
            "StoppingCondition": {"MaxRuntimeInSeconds": 60},
        }
    )


def _submit_service_job(ctx, job_queue_arn, role_arn, bucket, quota_share_name, *, priority):
    batch = ctx.client("batch")
    job_name = ctx.unique_name("sim2real-batch-sj-")
    payload = _service_request_payload(ctx, role_arn, bucket, job_name)
    resp = batch.submit_service_job(
        jobName=job_name,
        jobQueue=job_queue_arn,
        serviceJobType="SAGEMAKER_TRAINING",
        serviceRequestPayload=payload,
        quotaShareName=quota_share_name,
        schedulingPriority=priority,
    )
    job_id = resp["jobId"]
    _poll_until(
        lambda: batch.describe_service_job(jobId=job_id),
        lambda job: job["status"] is not None,
        timeout_s=30,
        interval_s=2,
        desc="service job visible via DescribeServiceJob",
    )
    return job_id


def _restricted_batch_client(ctx):
    """Assume a policy-less role trusted by this account; return its batch client and role ARN.

    Every action, including batch:TerminateServiceJob, is implicitly denied for it."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-batch-noperm-role-")
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]

    def _cleanup():
        try:
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)

    def _try_assume():
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-batch-noperm")
        except ClientError:
            return None

    assumed = _poll_until(
        _try_assume,
        lambda resp: resp is not None,
        timeout_s=30,
        interval_s=3,
        desc="assume newly created no-permission role (IAM propagation)",
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
