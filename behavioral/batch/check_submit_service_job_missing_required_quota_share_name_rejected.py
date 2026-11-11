"""submit-service-job-missing-required-quota-share-name-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "submit-service-job-missing-required-quota-share-name-rejected"
GROUP = "server-side"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """SubmitServiceJob omitting quotaShareName on a quota-share queue fails with ClientException.

    No job is created; a request with quotaShareName is accepted and persisted on that queue."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    batch = ctx.client("batch")

    role_arn = _create_sagemaker_execution_role(ctx, "sim2real-batch-negrole-")

    sp = batch.create_scheduling_policy(
        name=ctx.unique_name("sim2real-batch-negsp-"),
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags={"sim2real-check": CHECK},
    )
    sp_arn = sp["arn"]
    ctx.on_cleanup(lambda: _delete_quiet(lambda: _retry_in_use(
        ctx, lambda: batch.delete_scheduling_policy(arn=sp_arn), teardown_deadline)))

    se_name = ctx.unique_name("sim2real-batch-negse-")
    batch.create_service_environment(
        serviceEnvironmentName=se_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"maxCapacity": 1, "capacityUnit": "ml.m5.large"}],
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _disable_and_delete_service_environment(ctx, se_name, teardown_deadline))
    _wait_for_service_environment_status(ctx, se_name, "VALID", timeout_s=180)

    jq_name = ctx.unique_name("sim2real-batch-negjq-")
    jq = batch.create_job_queue(
        jobQueueName=jq_name,
        priority=1,
        jobQueueType="SAGEMAKER_TRAINING",
        schedulingPolicyArn=sp_arn,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": se_name}],
        tags={"sim2real-check": CHECK},
    )
    jq_arn = jq["jobQueueArn"]
    ctx.on_cleanup(lambda: _disable_and_delete_job_queue(ctx, jq_name, teardown_deadline))
    _wait_for_job_queue_status(ctx, jq_name, "VALID", timeout_s=180)

    quota_share = ctx.unique_name("sim2real-batch-negqs-")
    qs = batch.create_quota_share(
        quotaShareName=quota_share,
        jobQueue=jq_name,
        capacityLimits=[{"maxCapacity": 1, "capacityUnit": "ml.m5.large"}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        tags={"sim2real-check": CHECK},
    )
    qs_arn = qs["quotaShareArn"]
    ctx.on_cleanup(lambda: _disable_and_delete_quota_share(ctx, batch, qs_arn, teardown_deadline))
    _wait_for_quota_share_status(ctx, qs_arn, "VALID", timeout_s=120)

    payload = _training_payload(ctx, role_arn, "negtest")

    # Break exactly one thing: omit the now-mandatory quotaShareName.
    error = _error(
        lambda: batch.submit_service_job(
            jobName=ctx.unique_name("sim2real-batch-negsj-"),
            jobQueue=jq_name,
            serviceJobType="SAGEMAKER_TRAINING",
            serviceRequestPayload=json.dumps(payload),
        )
    )
    code, message = error.get("Code"), error.get("Message")
    assert code == "ClientException", f"expected ClientException, got {code!r}"
    assert message == (
        "Job without quotaShareName cannot be submitted to a job queue with quota share scheduling policy."
    ), f"expected the exact missing-quotaShareName message, got {message!r}"

    # Effect absent: no service job for this queue was created by the rejected call.
    listed = batch.list_service_jobs(jobQueue=jq_name)["jobSummaryList"]
    assert listed == [], f"a job appears to have been created despite rejection: {listed!r}"

    # Positive control: the same queue accepts a request that DOES supply quotaShareName.
    # Retried (bounded, not slept) because the IAM role's trust policy can still be propagating
    # to SageMaker, which SubmitServiceJob surfaces as a transient ClientException.
    accepted = _submit_service_job_with_retry(
        batch,
        jobName=ctx.unique_name("sim2real-batch-negsj-ok-"),
        jobQueue=jq_name,
        serviceJobType="SAGEMAKER_TRAINING",
        quotaShareName=quota_share,
        schedulingPriority=1,
        serviceRequestPayload=json.dumps(_training_payload(ctx, role_arn, "negtest-ok")),
    )
    job_id = accepted["jobId"]
    assert job_id
    ctx.on_cleanup(lambda jid=job_id: _terminate_service_job_quiet(ctx, jid))

    described = batch.describe_service_job(jobId=job_id)
    assert described["jobId"] == job_id
    assert described["jobQueue"] == jq_arn, (
        f"expected jobQueue={jq_arn!r}, got {described.get('jobQueue')!r}"
    )
    assert described["quotaShareName"] == quota_share, (
        f"expected quotaShareName={quota_share!r}, got {described.get('quotaShareName')!r}"
    )


def _error(fn):
    """Call fn(); return the botocore Error dict. An unexpected SUCCESS raises rather than
    returning a falsy sentinel, so an over-permissive target cannot pass acceptance off as an
    ordinary error-code mismatch."""
    try:
        result = fn()
    except Exception as exc:  # botocore.exceptions.ClientError
        error = getattr(exc, "response", {}).get("Error", {})
        if error.get("Code") is None:
            raise
        return error
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _submit_service_job_with_retry(batch, *, attempts: int = 8, delay_s: float = 8.0, **kwargs):
    """SubmitServiceJob can transiently answer ClientException while the IAM role's trust policy
    is still propagating to SageMaker; retry on that specific code with a bounded deadline rather
    than sleeping blindly before the first attempt."""
    last_err = None
    for attempt in range(attempts):
        try:
            return batch.submit_service_job(**kwargs)
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code != "ClientException" or attempt == attempts - 1:
                raise
            last_err = exc
            time.sleep(delay_s)
    raise AssertionError(f"submit_service_job never succeeded after retries: {last_err!r}")


def _wait_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_sagemaker_execution_role(ctx: Any, prefix: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
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
    return role["Role"]["Arn"]


def _training_payload(ctx: Any, role_arn: str, tag: str) -> dict:
    training_image = f"123456789012.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-training:2.0.0-cpu-py310"
    return {
        "TrainingJobName": ctx.unique_name(f"sim2real-batch-tj-{tag}-"),
        "RoleArn": role_arn,
        "AlgorithmSpecification": {
            "TrainingInputMode": "File",
            "TrainingImage": training_image,
            "ContainerEntrypoint": ["echo", f"hello-{tag}"],
        },
        "ResourceConfig": {"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 1},
        "OutputDataConfig": {"S3OutputPath": f"s3://sim2real-batch-unused-{tag}/output"},
        "StoppingCondition": {"MaxRuntimeInSeconds": 60},
    }


def _wait_for_service_environment_status(ctx: Any, name: str, status: str, *, timeout_s: float) -> None:
    batch = ctx.client("batch")

    def _probe():
        resp = batch.describe_service_environments(serviceEnvironments=[name])
        envs = resp.get("serviceEnvironments", [])
        return envs[0] if envs else None

    result = _wait_until(_probe, lambda r: r is not None and r["status"] == status, timeout_s=timeout_s, interval_s=3)
    assert result["status"] == status


def _wait_for_job_queue_status(ctx: Any, name: str, status: str, *, timeout_s: float) -> None:
    batch = ctx.client("batch")

    def _probe():
        resp = batch.describe_job_queues(jobQueues=[name])
        queues = resp.get("jobQueues", [])
        return queues[0] if queues else None

    result = _wait_until(_probe, lambda r: r is not None and r["status"] == status, timeout_s=timeout_s, interval_s=3)
    assert result["status"] == status


def _wait_for_quota_share_status(ctx: Any, arn: str, status: str, *, timeout_s: float) -> None:
    batch = ctx.client("batch")

    def _probe():
        return batch.describe_quota_share(quotaShareArn=arn)

    result = _wait_until(_probe, lambda r: r["status"] == status, timeout_s=timeout_s, interval_s=3)
    assert result["status"] == status


def _disable_and_delete_service_environment(ctx: Any, name: str, teardown_deadline) -> None:
    batch = ctx.client("batch")
    try:
        batch.update_service_environment(serviceEnvironment=name, state="DISABLED")
        _wait_for_service_environment_status(ctx, name, "VALID", timeout_s=120)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    _retry_in_use(ctx, lambda: batch.delete_service_environment(serviceEnvironment=name), teardown_deadline)


def _disable_and_delete_job_queue(ctx: Any, name: str, teardown_deadline) -> None:
    batch = ctx.client("batch")
    try:
        batch.update_job_queue(jobQueue=name, state="DISABLED")
        _wait_for_job_queue_status(ctx, name, "VALID", timeout_s=120)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    _retry_in_use(ctx, lambda: batch.delete_job_queue(jobQueue=name), teardown_deadline)


def _disable_and_delete_quota_share(ctx: Any, batch, arn: str, teardown_deadline) -> None:
    # DeleteQuotaShare requires the quota share to be DISABLED first (mirrors
    # DeleteJobQueue's own disable-before-delete requirement).
    try:
        batch.update_quota_share(quotaShareArn=arn, state="DISABLED")
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ClientException"
            and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
        ):
            raise
        return
    _wait_for_quota_share_status(ctx, arn, "VALID", timeout_s=120)
    _retry_in_use(ctx, lambda: batch.delete_quota_share(quotaShareArn=arn), teardown_deadline)


def _terminate_service_job_quiet(ctx: Any, job_id: str) -> None:
    batch = ctx.client("batch")
    batch.terminate_service_job(jobId=job_id, reason="sim2real-behavioral-cleanup")


def _delete_quiet(fn) -> None:
    fn()


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
