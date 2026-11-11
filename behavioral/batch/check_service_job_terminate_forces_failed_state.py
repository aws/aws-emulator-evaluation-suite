"""service-job-terminate-forces-failed-state."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-job-terminate-forces-failed-state"
GROUP = "state-machine"
SERVICES = ["batch"]
_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TerminateServiceJob forces a non-terminal service job into terminal FAILED status."""
    batch = ctx.client("batch")
    queue = _create_quota_managed_job_queue(ctx)
    role_arn = _create_sagemaker_role(ctx)
    job_id = _submit_service_job(
        ctx, queue["jobQueueArn"], role_arn, queue["quotaShareName"], max_runtime=600
    )

    before = batch.describe_service_job(jobId=job_id)
    assert before["status"] in {
        "SUBMITTED",
        "PENDING",
        "RUNNABLE",
        "SCHEDULED",
        "STARTING",
        "RUNNING",
    }

    batch.terminate_service_job(jobId=job_id, reason="sim2real-behavioral-terminate-test")

    terminated = _poll_service_job_terminal(ctx, job_id, timeout_s=300)
    assert terminated["status"] == "FAILED", f"expected FAILED, got {terminated['status']!r}"
    assert "sim2real-behavioral-terminate-test" in (terminated.get("statusReason") or ""), (
        f"expected the supplied termination reason echoed verbatim, got {terminated.get('statusReason')!r}"
    )


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
        tags=_MANAGED_TAGS,
    )
    sp_arn = sp["arn"]
    ctx.on_cleanup(lambda: _safe_delete_scheduling_policy(ctx, sp_arn))

    se_name = ctx.unique_name("sim2real-batch-se-")
    se = batch.create_service_environment(
        serviceEnvironmentName=se_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"maxCapacity": 2, "capacityUnit": "ml.c5.xlarge"}],
        tags=_MANAGED_TAGS,
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
        tags=_MANAGED_TAGS,
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

    # Real AWS Batch rejects SubmitServiceJob against a job queue backed by a
    # quota-management scheduling policy unless the job carries a quotaShareName, so
    # the queue needs a quota share of its own before any job can be submitted to it.
    qs_name = _create_quota_share(ctx, batch, jq_arn)

    return {
        "jobQueueArn": jq_arn,
        "jobQueueName": jq_name,
        "serviceEnvironmentArn": se_arn,
        "schedulingPolicyArn": sp_arn,
        "quotaShareName": qs_name,
    }


def _create_quota_share(ctx, batch, job_queue_arn):
    qs_name = ctx.unique_name("sim2real-batch-qs-")
    qs = batch.create_quota_share(
        quotaShareName=qs_name,
        jobQueue=job_queue_arn,
        capacityLimits=[{"maxCapacity": 2, "capacityUnit": "ml.c5.xlarge"}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        tags=_MANAGED_TAGS,
    )
    qs_arn = qs["quotaShareArn"]
    ctx.on_cleanup(lambda: _safe_delete_quota_share(batch, qs_arn))

    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        desc = batch.describe_quota_share(quotaShareArn=qs_arn)
        if desc["status"] == "VALID":
            return qs_name
        if desc["status"] == "INVALID":
            raise AssertionError(f"quota share became INVALID: {desc}")
        time.sleep(3)
    raise AssertionError("quota share did not reach VALID in time")


def _safe_delete_quota_share(batch, arn):
    try:
        batch.update_quota_share(quotaShareArn=arn, state="DISABLED")
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ClientException"
            and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
        ):
            raise
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            desc = batch.describe_quota_share(quotaShareArn=arn)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
            return
        if desc.get("status") in ("VALID", "INVALID"):
            break
        time.sleep(3)
    batch.delete_quota_share(quotaShareArn=arn)


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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )
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
    return role_arn


def _submit_service_job(ctx, queue_arn, role_arn, quota_share_name, max_runtime=60):
    batch = ctx.client("batch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    payload = {
        "TrainingJobName": ctx.unique_name("sim2real-batch-tj-")[:63],
        "RoleArn": role_arn,
        "AlgorithmSpecification": {
            "TrainingInputMode": "File",
            "TrainingImage": f"123456789012.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-training:2.0.0-cpu-py310",
            "ContainerEntrypoint": ["sleep", "600"],
        },
        "ResourceConfig": {"InstanceType": "ml.c5.xlarge", "InstanceCount": 1, "VolumeSizeInGB": 1},
        "OutputDataConfig": {"S3OutputPath": f"s3://sim2real-batch-{account_id}/output"},
        "StoppingCondition": {"MaxRuntimeInSeconds": max_runtime},
    }
    resp = _submit_service_job_with_role_retry(
        batch,
        jobQueue=queue_arn,
        jobName=ctx.unique_name("sim2real-batch-sj-"),
        serviceJobType="SAGEMAKER_TRAINING",
        serviceRequestPayload=json.dumps(payload),
        quotaShareName=quota_share_name,
        # Real AWS Batch rejects a job submitted to a queue backed by a quota-management
        # scheduling policy unless it also carries a schedulingPriority.
        schedulingPriority=10,
        retryStrategy={"attempts": 1},
        timeoutConfig={"attemptDurationSeconds": max_runtime + 120},
        tags=_MANAGED_TAGS,
    )
    job_id = resp["jobId"]
    ctx.on_cleanup(lambda: _safe_terminate_service_job(ctx, job_id))
    return job_id


def _submit_service_job_with_role_retry(batch, *, timeout_s=60.0, interval_s=5.0, **kwargs):
    """The role's trust policy can take a few seconds to propagate to Batch's own
    role-usability check, so retry on that specific rejection instead of blindly
    sleeping before the first submission attempt."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return batch.submit_service_job(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            message = exc.response.get("Error", {}).get("Message", "")
            if code != "ClientException" or "role" not in message.lower() or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _safe_terminate_service_job(ctx, job_id):
    batch = ctx.client("batch")
    batch.terminate_service_job(jobId=job_id, reason="check cleanup")


def _poll_service_job_terminal(ctx, job_id, timeout_s=300):
    batch = ctx.client("batch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = batch.describe_service_job(jobId=job_id)
        last = resp
        if resp["status"] in {"SUCCEEDED", "FAILED"}:
            return resp
        time.sleep(5)
    raise AssertionError(f"service job did not reach a terminal state, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
