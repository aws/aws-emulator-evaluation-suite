"""delete-quota-share-unknown-id-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-quota-share-unknown-id-fails"
GROUP = "error-semantics"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteQuotaShare on an unknown ARN is accepted idempotently (empirically verified
    against real AWS: it does NOT raise ClientException the way Describe/Update do), and
    critically does not materialize any resource as a side effect."""
    batch = ctx.client("batch")
    queue = _create_quota_managed_job_queue(ctx)

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = (
        f"arn:aws:batch:{ctx.region}:{account_id}:job-queue/"
        f"{ctx.unique_name('sim2real-batch-nonexistent-jq-')}/quota-share/"
        f"{ctx.unique_name('sim2real-batch-nonexistent-qs-')}"
    )

    # DeleteQuotaShare on an unknown ARN must NOT raise -- real AWS accepts it
    # idempotently (unlike DescribeQuotaShare/UpdateQuotaShare, which do reject
    # unknown ids with ClientException).
    batch.delete_quota_share(quotaShareArn=bogus_arn)

    # Calling it again is also accepted -- not just accepted-once.
    batch.delete_quota_share(quotaShareArn=bogus_arn)

    # "Accepted" must not mean "materialized": the bogus arn must never resolve.
    describe_code, describe_message = _error_code(lambda: batch.describe_quota_share(quotaShareArn=bogus_arn))
    assert describe_code == "ClientException", (
        f"expected ClientException from Describe on a never-created quota share, got {describe_code!r}"
    )
    expected = f"{bogus_arn} does not exist."
    assert describe_message == expected, f"expected message {expected!r}, got {describe_message!r}"

    # Positive control: a real (disabled) quota share deletes successfully.
    real = batch.create_quota_share(
        quotaShareName=ctx.unique_name("sim2real-batch-qs-"),
        jobQueue=queue["jobQueueArn"],
        capacityLimits=[{"maxCapacity": 1, "capacityUnit": "ml.m5.large"}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        tags=_MANAGED_TAGS,
    )
    real_arn = real["quotaShareArn"]
    ctx.on_cleanup(lambda: _best_effort_delete(ctx, real_arn))

    _wait_quota_share_status(ctx, real_arn, {"VALID"})
    batch.update_quota_share(quotaShareArn=real_arn, state="DISABLED")
    _wait_quota_share_status(ctx, real_arn, {"VALID"})

    batch.delete_quota_share(quotaShareArn=real_arn)
    _wait_quota_share_deleted(ctx, real_arn)



def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused with a ClientError, but it succeeded")


def _retry_refused(call, *, timeout_s=60):
    """Run a Batch teardown call, where "does not exist" means already gone.

    Batch answers ClientException while a dependency drains: retry that every 2 s, then raise.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                return None
            if err["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _best_effort_delete(ctx, arn):
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
    _retry_refused(lambda: batch.delete_quota_share(quotaShareArn=arn))


def _wait_quota_share_status(ctx, arn, target_statuses, timeout_s=120):
    batch = ctx.client("batch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = batch.describe_quota_share(quotaShareArn=arn)
        last = resp
        if resp["status"] in target_statuses:
            return resp
        if resp["status"] == "INVALID":
            raise AssertionError(f"quota share became INVALID: {resp}")
        time.sleep(3)
    raise AssertionError(f"quota share never reached {target_statuses}, last={last}")


def _wait_quota_share_deleted(ctx, arn, timeout_s=120):
    batch = ctx.client("batch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            batch.describe_quota_share(quotaShareArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ClientException":
                return
            raise
        time.sleep(3)
    raise AssertionError("quota share was not reported not-found after delete")


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
    _retry_refused(lambda: batch.delete_scheduling_policy(arn=arn))


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
        capacityLimits=[{"maxCapacity": 2, "capacityUnit": "ml.m5.large"}],
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
        _retry_refused(lambda: batch.delete_service_environment(serviceEnvironment=se_arn), timeout_s=90)

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
        _retry_refused(lambda: batch.delete_job_queue(jobQueue=jq_arn), timeout_s=90)

    ctx.on_cleanup(_cleanup_jq)
    _wait_job_queue_valid(ctx, jq_arn)
    return {
        "jobQueueArn": jq_arn,
        "jobQueueName": jq_name,
        "serviceEnvironmentArn": se_arn,
        "schedulingPolicyArn": sp_arn,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
