"""list-quota-shares-invalid-filter-combination-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-quota-shares-invalid-filter-combination-fails"
GROUP = "error-semantics"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListQuotaShares refuses a valid jobQueue paired with an unissued nextToken (ClientException).

    Plain listings before and after the refusal return the same quota shares.
    """
    batch = ctx.client("batch")
    stack = _setup_quota_management_job_queue(ctx)
    jq_arn = stack["job_queue_arn"]

    real_arn = _create_quota_share(ctx, jq_arn)
    _wait_quota_share_status(batch, real_arn, {"VALID", "INVALID"})

    before = batch.list_quota_shares(jobQueue=jq_arn)["quotaShares"]
    assert real_arn in [s["quotaShareArn"] for s in before]

    code, message = _error_code(
        lambda: batch.list_quota_shares(jobQueue=jq_arn, nextToken="sim2real-not-a-real-token")
    )
    assert code == "ClientException", f"expected ClientException for invalid nextToken, got {code}"
    assert message == "Error processing next token", f"unexpected message {message!r}"

    after = batch.list_quota_shares(jobQueue=jq_arn)["quotaShares"]
    assert real_arn in [s["quotaShareArn"] for s in after]
    assert len(after) == len(before)


def _error_code(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises,
    so accepting input AWS refuses is never reported as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected ListQuotaShares to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_quota_scheduling_policy(ctx):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-qmsp-")
    arn = batch.create_scheduling_policy(
        name=name, quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"}, tags=_MANAGED_TAGS
    )["arn"]
    ctx.on_cleanup(lambda: batch.delete_scheduling_policy(arn=arn))
    return arn


def _create_sagemaker_service_environment(ctx):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-qmse-")
    arn = batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 1}],
        tags=_MANAGED_TAGS,
    )["serviceEnvironmentArn"]

    def _cleanup():
        try:
            batch.update_service_environment(serviceEnvironment=arn, state="DISABLED")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
        _wait_until(
            lambda: batch.describe_service_environments(serviceEnvironments=[arn])["serviceEnvironments"],
            lambda envs: not envs or envs[0]["status"] in ("VALID", "INVALID"),
        )
        batch.delete_service_environment(serviceEnvironment=arn)
        _wait_until(
            lambda: batch.describe_service_environments(serviceEnvironments=[arn])["serviceEnvironments"],
            lambda envs: not envs,
            timeout_s=300.0,
        )

    ctx.on_cleanup(_cleanup)
    _wait_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[arn])["serviceEnvironments"],
        lambda envs: envs and envs[0]["status"] in ("VALID", "INVALID"),
    )
    return name, arn


def _create_sagemaker_job_queue(ctx, scheduling_policy_arn, service_environment_name):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-qmjq-")
    arn = batch.create_job_queue(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        state="ENABLED",
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": service_environment_name}],
        schedulingPolicyArn=scheduling_policy_arn,
        tags=_MANAGED_TAGS,
    )["jobQueueArn"]

    def _cleanup():
        try:
            batch.update_job_queue(jobQueue=arn, state="DISABLED")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
        _wait_until(
            lambda: batch.describe_job_queues(jobQueues=[arn])["jobQueues"],
            lambda qs: not qs or qs[0]["status"] in ("VALID", "INVALID"),
        )
        batch.delete_job_queue(jobQueue=arn)
        # The scheduling policy and service environment refuse deletion while a job queue
        # still references them, so wait until the queue is fully gone.
        _wait_until(
            lambda: batch.describe_job_queues(jobQueues=[arn])["jobQueues"],
            lambda qs: not qs,
            timeout_s=300.0,
        )

    ctx.on_cleanup(_cleanup)
    _wait_until(
        lambda: batch.describe_job_queues(jobQueues=[arn])["jobQueues"],
        lambda qs: qs and qs[0]["status"] in ("VALID", "INVALID"),
    )
    return name, arn


def _setup_quota_management_job_queue(ctx):
    sp_arn = _create_quota_scheduling_policy(ctx)
    se_name, se_arn = _create_sagemaker_service_environment(ctx)
    jq_name, jq_arn = _create_sagemaker_job_queue(ctx, sp_arn, se_name)
    return {
        "scheduling_policy_arn": sp_arn,
        "service_environment_arn": se_arn,
        "job_queue_name": jq_name,
        "job_queue_arn": jq_arn,
    }


def _create_quota_share(ctx, job_queue, name=None, max_capacity=1, strategy="RESERVE", in_share_preemption="DISABLED"):
    batch = ctx.client("batch")
    name = name or ctx.unique_name("sim2real-batch-qs-")
    arn = batch.create_quota_share(
        quotaShareName=name,
        jobQueue=job_queue,
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": max_capacity}],
        resourceSharingConfiguration={"strategy": strategy},
        preemptionConfiguration={"inSharePreemption": in_share_preemption},
        tags=_MANAGED_TAGS,
    )["quotaShareArn"]

    def _cleanup():
        try:
            batch.update_quota_share(quotaShareArn=arn, state="DISABLED")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
            ):
                raise
        try:
            _wait_quota_share_status(batch, arn, {"VALID", "INVALID"}, timeout_s=60.0)
        except AssertionError:
            pass
        batch.delete_quota_share(quotaShareArn=arn)
        # The job queue refuses deletion while a quota share still references it.
        _wait_until(lambda: _quota_share_status_or_gone(batch, arn), lambda s: s in (None, "DELETED"), timeout_s=300.0)

    ctx.on_cleanup(_cleanup)
    return arn


def _quota_share_status_or_gone(batch, arn):
    try:
        return batch.describe_quota_share(quotaShareArn=arn).get("status")
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
        return None


def _wait_quota_share_status(batch, arn, target_statuses, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = batch.describe_quota_share(quotaShareArn=arn)
        if last.get("status") in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"quota share {arn} did not reach {target_statuses}; last status={last.get('status') if last else None}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
