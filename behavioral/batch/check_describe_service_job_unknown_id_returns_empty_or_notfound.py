"""describe-service-job-unknown-id-returns-empty-or-notfound."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-service-job-unknown-id-returns-empty-or-notfound"
GROUP = "error-semantics"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeServiceJob for an unknown jobId returns ClientException (not a 500) while a real
    service job resolves; DescribeJobs instead omits an unknown id and returns the real job with it.
    """
    batch = ctx.client("batch")

    real_service_job_id = _submit_minimal_service_job(ctx, batch)
    real_resp = batch.describe_service_job(jobId=real_service_job_id)
    assert real_resp["jobId"] == real_service_job_id, (
        f"expected DescribeServiceJob to succeed for a real service job id, got {real_resp!r}"
    )

    bogus_service_job_id = str(uuid.uuid4())
    code, message = _error_code(lambda: batch.describe_service_job(jobId=bogus_service_job_id))
    assert code == "ClientException", f"expected ClientException for unknown service job id, got {code}"
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    expected = f"arn:aws:batch:{ctx.region}:{account_id}:service-job/{bogus_service_job_id} does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    real_regular_job_id = _submit_minimal_regular_job(ctx, batch)
    bogus_regular_job_id = str(uuid.uuid4())
    resp = batch.describe_jobs(jobs=[real_regular_job_id, bogus_regular_job_id])
    returned_ids = {j["jobId"] for j in resp["jobs"]}
    assert returned_ids == {real_regular_job_id}, (
        f"expected only the real job id back, got {returned_ids} "
        f"(real={real_regular_job_id!r}, bogus={bogus_regular_job_id!r})"
    )


# ===== helpers =====

def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises AssertionError."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused with a ClientError, but it succeeded")


def _gone(exc):
    """A Batch/IAM error that means the resource is already gone."""
    err = exc.response["Error"]
    return err["Code"] == "NoSuchEntity" or (
        err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")
    )


def _safe(fn):
    """Run fn(); only a resource that is already gone is ignored, every other failure raises."""
    try:
        fn()
    except ClientError as exc:
        if not _gone(exc):
            raise


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s (last={last!r})")


def _retry_delete(fn, *, timeout_s, interval_s=2):
    """Retry a delete Batch refuses (ClientException) to a deadline, then raise; gone is done.

    Batch refuses these deletes while a dependent (unterminated job, referencing queue) settles.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if _gone(exc):
                return
            if exc.response["Error"]["Code"] != "ClientException" or time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


# -- SAGEMAKER_TRAINING service job apparatus: only what SubmitServiceJob requires --

def _submit_minimal_service_job(ctx, batch):
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    sp_name = ctx.unique_name("sim2real-batch-sp-")
    sp_arn = batch.create_scheduling_policy(
        name=sp_name,
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags=_MANAGED_TAGS,
    )["arn"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: batch.delete_scheduling_policy(arn=sp_arn), timeout_s=60))

    se_name = ctx.unique_name("sim2real-batch-se-")
    se_arn = batch.create_service_environment(
        serviceEnvironmentName=se_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        # SAGEMAKER_TRAINING requires capacityLimits, which makes the environment
        # "quota management compatible" and forces every queue bound to it (below)
        # to carry a quota-management schedulingPolicyArn.
        capacityLimits=[{"maxCapacity": 1, "capacityUnit": "ml.m5.large"}],
        tags=_MANAGED_TAGS,
    )["serviceEnvironmentArn"]
    ctx.on_cleanup(lambda: _teardown_service_environment(batch, se_arn))
    _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[se_arn])["serviceEnvironments"][0],
        lambda e: e["status"] == "VALID",
        timeout_s=180,
        description=f"service environment {se_name} VALID",
    )

    jq_name = ctx.unique_name("sim2real-batch-sjq-")
    jq_arn = batch.create_job_queue(
        jobQueueName=jq_name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": se_arn}],
        schedulingPolicyArn=sp_arn,
        tags=_MANAGED_TAGS,
    )["jobQueueArn"]
    ctx.on_cleanup(lambda: _teardown_job_queue(batch, jq_arn))
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[jq_arn])["jobQueues"][0],
        lambda q: q["status"] == "VALID",
        timeout_s=180,
        description=f"job queue {jq_name} VALID",
    )

    qs_name = ctx.unique_name("sim2real-batch-qs-")
    qs_arn = batch.create_quota_share(
        quotaShareName=qs_name,
        jobQueue=jq_name,
        capacityLimits=[{"maxCapacity": 1, "capacityUnit": "ml.m5.large"}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        tags=_MANAGED_TAGS,
    )["quotaShareArn"]
    ctx.on_cleanup(lambda: _teardown_quota_share(batch, qs_arn))
    _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=qs_arn),
        lambda d: d["status"] == "VALID",
        timeout_s=180,
        description=f"quota share {qs_name} VALID",
    )

    job_name = ctx.unique_name("sim2real-batch-sj-")
    submitted = batch.submit_service_job(
        jobName=job_name,
        jobQueue=jq_name,
        serviceJobType="SAGEMAKER_TRAINING",
        serviceRequestPayload=_service_payload(account_id, ctx.region, job_name),
        quotaShareName=qs_name,
        # A queue backed by a quota-management scheduling policy rejects a job with
        # no schedulingPriority (ClientException), regardless of jobQueue.
        schedulingPriority=10,
        timeoutConfig={"attemptDurationSeconds": 60},
        tags=_MANAGED_TAGS,
    )
    job_id = submitted["jobId"]
    ctx.on_cleanup(lambda: _terminate_service_job_and_wait(batch, job_id))
    return job_id


def _terminate_service_job_and_wait(batch, job_id, timeout_s=30):
    # The job queue below cannot be deleted while this job is still non-terminal
    # on it, so give termination a bounded chance to actually land first.
    _safe(lambda: batch.terminate_service_job(jobId=job_id, reason="sim2real-audit-cleanup"))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if batch.describe_service_job(jobId=job_id)["status"] in ("SUCCEEDED", "FAILED"):
            return
        time.sleep(2)


def _service_payload(account_id, region, job_name):
    # RoleArn and S3OutputPath are never assumed or written to: the check only
    # needs SubmitServiceJob to accept the request and hand back a real jobId
    # that DescribeServiceJob resolves -- it does not wait for SageMaker to act
    # on the payload, and terminates the job in cleanup regardless of outcome.
    return json.dumps(
        {
            "TrainingJobName": job_name,
            "RoleArn": f"arn:aws:iam::{account_id}:role/sim2real-nonexistent-sagemaker-role",
            "AlgorithmSpecification": {
                "TrainingInputMode": "File",
                "TrainingImage": f"123456789012.dkr.ecr.{region}.amazonaws.com/pytorch-training:2.1.0-cpu-py310",
                "ContainerEntrypoint": ["sleep", "30"],
            },
            "ResourceConfig": {"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 1},
            "OutputDataConfig": {"S3OutputPath": f"s3://sim2real-nonexistent-bucket/{job_name}/output"},
            "StoppingCondition": {"MaxRuntimeInSeconds": 60},
        }
    )


def _teardown_service_environment(batch, se_arn, timeout_s=180):
    _safe(lambda: batch.update_service_environment(serviceEnvironment=se_arn, state="DISABLED"))
    _retry_delete(
        lambda: batch.delete_service_environment(serviceEnvironment=se_arn), timeout_s=timeout_s
    )


def _teardown_job_queue(batch, jq_arn, timeout_s=120):
    _safe(lambda: batch.update_job_queue(jobQueue=jq_arn, state="DISABLED"))
    _retry_delete(lambda: batch.delete_job_queue(jobQueue=jq_arn), timeout_s=timeout_s)


def _teardown_quota_share(batch, qs_arn, timeout_s=60):
    _safe(lambda: batch.update_quota_share(quotaShareArn=qs_arn, state="DISABLED"))
    _retry_delete(lambda: batch.delete_quota_share(quotaShareArn=qs_arn), timeout_s=timeout_s)


# -- UNMANAGED compute environment apparatus: only what SubmitJob requires --

_UNMANAGED_ROLE_NAME = "sim2real-behav-batch-service-role"
_BATCH_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole"
_BATCH_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "batch.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _unmanaged_service_role_arn(ctx):
    """Create-or-adopt a customer-managed Batch service role for UNMANAGED CEs.

    Cleanup is registered only when this run creates the role, so an adopted role is never deleted.
    """
    iam = ctx.client("iam")
    try:
        return iam.get_role(RoleName=_UNMANAGED_ROLE_NAME)["Role"]["Arn"]
    except ClientError:
        pass
    try:
        arn = iam.create_role(
            RoleName=_UNMANAGED_ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(_BATCH_TRUST_POLICY),
            Description="SimParity behavioral suite: Batch service role for UNMANAGED CEs",
            Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
        )["Role"]["Arn"]
    except ClientError:
        return iam.get_role(RoleName=_UNMANAGED_ROLE_NAME)["Role"]["Arn"]
    _safe(lambda: iam.attach_role_policy(RoleName=_UNMANAGED_ROLE_NAME, PolicyArn=_BATCH_SERVICE_POLICY))
    ctx.on_cleanup(lambda: _delete_shared_role(ctx))
    # A brand-new role is not instantly assumable by Batch; the caller retries
    # CreateComputeEnvironment on "cannot be assumed" instead of sleeping here.
    return arn


def _delete_shared_role(ctx):
    iam = ctx.client("iam")
    _safe(lambda: iam.detach_role_policy(RoleName=_UNMANAGED_ROLE_NAME, PolicyArn=_BATCH_SERVICE_POLICY))
    _safe(lambda: iam.delete_role(RoleName=_UNMANAGED_ROLE_NAME))


def _submit_minimal_regular_job(ctx, batch):
    role = _unmanaged_service_role_arn(ctx)

    ce_name = ctx.unique_name("sim2real-batch-ce-unmgd-")
    last_exc = None
    ce_arn = None
    for attempt in range(8):
        try:
            ce_arn = batch.create_compute_environment(
                computeEnvironmentName=ce_name,
                type="UNMANAGED",
                state="ENABLED",
                serviceRole=role,
                tags=_MANAGED_TAGS,
            )["computeEnvironmentArn"]
            break
        except ClientError as exc:
            msg = str(exc).lower()
            transient = (
                "cannot be assumed" in msg
                or "assumerole" in msg
                or "does not have permission" in msg
            )
            if not transient or attempt == 7:
                raise
            last_exc = exc
            time.sleep(5)
    if ce_arn is None:  # pragma: no cover - loop always breaks or raises
        raise last_exc
    ctx.on_cleanup(lambda: _teardown_ce(batch, ce_name))
    _poll_until(
        lambda: batch.describe_compute_environments(computeEnvironments=[ce_name])["computeEnvironments"][0],
        lambda ce: ce["status"] in ("VALID", "INVALID"),
        timeout_s=120,
        description=f"compute environment {ce_name} settled",
    )

    jq_name = ctx.unique_name("sim2real-batch-jq-")
    jq_arn = batch.create_job_queue(
        jobQueueName=jq_name,
        state="ENABLED",
        priority=10,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
        tags=_MANAGED_TAGS,
    )["jobQueueArn"]
    ctx.on_cleanup(lambda: _teardown_job_queue(batch, jq_arn))
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[jq_arn])["jobQueues"][0],
        lambda q: q["status"] == "VALID",
        timeout_s=120,
        description=f"job queue {jq_name} VALID",
    )

    jd_name = ctx.unique_name("sim2real-batch-jd-")
    jd = batch.register_job_definition(
        jobDefinitionName=jd_name,
        type="container",
        containerProperties={
            "image": "busybox:1.36",
            "command": ["echo", "hello"],
            "resourceRequirements": [
                {"type": "VCPU", "value": "1"},
                {"type": "MEMORY", "value": "512"},
            ],
        },
        tags=_MANAGED_TAGS,
    )
    jd_arn = jd["jobDefinitionArn"]
    jd_revision = jd["revision"]
    ctx.on_cleanup(
        lambda: _safe(lambda: batch.deregister_job_definition(jobDefinition=f"{jd_name}:{jd_revision}"))
    )

    job_name = ctx.unique_name("sim2real-batch-job-")
    job_id = batch.submit_job(
        jobName=job_name, jobQueue=jq_name, jobDefinition=jd_arn, tags=_MANAGED_TAGS
    )["jobId"]
    ctx.on_cleanup(lambda: _terminate_job_and_wait(batch, job_id))
    return job_id


def _terminate_job_and_wait(batch, job_id, timeout_s=20):
    # The job queue below cannot be deleted while this job is still non-terminal
    # on it, so give termination a bounded chance to actually land first.
    _safe(lambda: batch.terminate_job(jobId=job_id, reason="sim2real-audit-cleanup"))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        jobs = batch.describe_jobs(jobs=[job_id])["jobs"]
        if not jobs or jobs[0]["status"] in ("SUCCEEDED", "FAILED"):
            return
        time.sleep(2)


def _teardown_ce(batch, ce_name, timeout_s=180):
    _safe(lambda: batch.update_compute_environment(computeEnvironment=ce_name, state="DISABLED"))
    _retry_delete(
        lambda: batch.delete_compute_environment(computeEnvironment=ce_name), timeout_s=timeout_s
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
