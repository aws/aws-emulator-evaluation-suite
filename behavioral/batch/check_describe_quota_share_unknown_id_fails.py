"""describe-quota-share-unknown-id-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-quota-share-unknown-id-fails"
GROUP = "error-semantics"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeQuotaShare for a quotaShareArn that doesn't correspond to any quota
    share returns ClientException with a resource-not-found reason, and does not
    disturb lookups of the real quota share on the same job queue."""
    batch = ctx.client("batch")
    stack = _setup_quota_management_job_queue(ctx)
    jq_arn = stack["job_queue_arn"]

    real_arn = _create_quota_share(ctx, jq_arn)
    _wait_quota_share_status(batch, real_arn, {"VALID", "INVALID"})

    # positive control: the real quota share describes fine.
    before = batch.describe_quota_share(quotaShareArn=real_arn)
    assert before["quotaShareArn"] == real_arn, f"expected positive control to describe {real_arn!r}, got {before!r}"

    # break exactly one thing: swap in a well-formed but nonexistent quota-share name
    # on the same job-queue ARN prefix.
    bogus_arn = real_arn.rsplit("/", 1)[0] + "/" + ctx.unique_name("does-not-exist-")
    code, message = _error(lambda: batch.describe_quota_share(quotaShareArn=bogus_arn))
    assert code == "ClientException", f"expected ClientException for unknown quota share id, got {code}"
    expected_message = f"{bogus_arn} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the real quota share is unaffected by the failed lookup.
    after = batch.describe_quota_share(quotaShareArn=real_arn)
    assert after["quotaShareArn"] == real_arn, f"expected unaffected describe of {real_arn!r}, got {after!r}"
    assert after["capacityLimits"] == before["capacityLimits"], (
        f"expected capacityLimits unchanged by failed lookup: before={before['capacityLimits']!r}, after={after['capacityLimits']!r}"
    )
    assert after["state"] == before["state"], (
        f"expected state unchanged by failed lookup: before={before['state']!r}, after={after['state']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but call succeeded and returned {result!r}")


def _retry_client_error(fn, timeout_s=300.0, interval_s=10.0):
    """Retry a teardown delete while Batch still reports a dependent relationship."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError:
            if time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


def _quota_share_gone(batch, arn):
    try:
        return batch.describe_quota_share(quotaShareArn=arn).get("status") == "DELETED"
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
        return True


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
    ctx.on_cleanup(lambda: _retry_client_error(lambda: batch.delete_scheduling_policy(arn=arn)))
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
        _retry_client_error(lambda: batch.delete_service_environment(serviceEnvironment=arn))
        _wait_until(
            lambda: batch.describe_service_environments(serviceEnvironments=[arn])["serviceEnvironments"],
            lambda envs: not envs or envs[0]["status"] == "DELETED",
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
        _retry_client_error(lambda: batch.delete_job_queue(jobQueue=arn))
        _wait_until(
            lambda: batch.describe_job_queues(jobQueues=[arn])["jobQueues"],
            lambda qs: not qs or qs[0]["status"] == "DELETED",
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
        _wait_until(
            lambda: batch.describe_quota_share(quotaShareArn=arn),
            lambda q: q.get("state") == "DISABLED" and q.get("status") in ("VALID", "INVALID"),
        )
        _retry_client_error(lambda: batch.delete_quota_share(quotaShareArn=arn))
        _wait_until(lambda: _quota_share_gone(batch, arn), bool, timeout_s=300.0)

    ctx.on_cleanup(_cleanup)
    return arn


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
