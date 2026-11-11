"""describe-unknown-quota-share-fails."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "describe-unknown-quota-share-fails"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeQuotaShare for a well-formed but non-existent quota share ARN returns
    ClientException, never an empty/absent-field success response — and a failed
    lookup on a bogus ARN does not disturb a lookup of a real quota share."""
    batch = ctx.client("batch")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    real_arn = _setup_real_quota_share(ctx)

    # positive control: the real quota share describes fine before the bogus lookup.
    before = batch.describe_quota_share(quotaShareArn=real_arn)
    assert before["quotaShareArn"] == real_arn

    # break exactly one thing: a well-formed ARN whose job queue AND quota share both
    # don't exist (distinct from a real-queue/fake-share-id ARN).
    bogus_arn = (
        f"arn:aws:batch:{ctx.region}:{account_id}:job-queue/"
        f"{ctx.unique_name('sim2real-batch-nope-q-')}/quota-share/"
        f"{ctx.unique_name('sim2real-batch-nope-qs-')}"
    )
    code, message = _error(lambda: batch.describe_quota_share(quotaShareArn=bogus_arn))
    assert code == "ClientException", f"expected ClientException for unknown quotaShareArn, got {code!r}"
    expected_message = f"{bogus_arn} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the real quota share is unaffected by the failed lookup.
    after = batch.describe_quota_share(quotaShareArn=real_arn)
    assert after["quotaShareArn"] == real_arn
    assert after["capacityLimits"] == before["capacityLimits"]
    assert after["state"] == before["state"]


from botocore.exceptions import ClientError

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch"}


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_service_environment(ctx):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-se-")
    batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"maxCapacity": 2, "capacityUnit": "ml.m6i.large"}],
        tags=_MANAGED_TAGS,
    )

    def _cleanup():
        try:
            batch.update_service_environment(serviceEnvironment=name, state="DISABLED")
            _poll_until(
                lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0],
                lambda se: se["state"] == "DISABLED",
                timeout_s=90,
            )
            batch.delete_service_environment(serviceEnvironment=name)
            _poll_until(
                lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"],
                lambda ses: len(ses) == 0,
                timeout_s=150,
            )
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0],
        lambda se: se["status"] == "VALID",
        timeout_s=90,
    )
    return name


def _create_scheduling_policy(ctx):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")
    arn = batch.create_scheduling_policy(
        name=name,
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags=_MANAGED_TAGS,
    )["arn"]

    def _cleanup():
        batch.delete_scheduling_policy(arn=arn)

    ctx.on_cleanup(_cleanup)
    return arn


def _create_job_queue(ctx, service_environment_name, scheduling_policy_arn, priority=1):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-jq-")
    resp = batch.create_job_queue(
        jobQueueName=name,
        priority=priority,
        jobQueueType="SAGEMAKER_TRAINING",
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": service_environment_name}],
        schedulingPolicyArn=scheduling_policy_arn,
        tags=_MANAGED_TAGS,
    )
    arn = resp["jobQueueArn"]

    def _cleanup():
        try:
            batch.update_job_queue(jobQueue=arn, state="DISABLED")
            _poll_until(
                lambda: batch.describe_job_queues(jobQueues=[arn])["jobQueues"][0],
                lambda jq: jq["state"] == "DISABLED",
                timeout_s=90,
            )
            batch.delete_job_queue(jobQueue=arn)
            _poll_until(
                lambda: batch.describe_job_queues(jobQueues=[arn])["jobQueues"],
                lambda jqs: len(jqs) == 0,
                timeout_s=180,
            )
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[arn])["jobQueues"][0],
        lambda jq: jq["status"] == "VALID",
        timeout_s=90,
    )
    return arn


def _create_quota_share(ctx, job_queue_arn, max_capacity=1, capacity_unit="ml.m6i.large"):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-qs-")
    resp = batch.create_quota_share(
        quotaShareName=name,
        jobQueue=job_queue_arn,
        capacityLimits=[{"maxCapacity": max_capacity, "capacityUnit": capacity_unit}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "ENABLED"},
        tags=_MANAGED_TAGS,
    )
    arn = resp["quotaShareArn"]

    def _cleanup():
        try:
            batch.update_quota_share(quotaShareArn=arn, state="DISABLED")
            _poll_until(
                lambda: batch.describe_quota_share(quotaShareArn=arn),
                lambda qs: qs["state"] == "DISABLED",
                timeout_s=90,
            )
            batch.delete_quota_share(quotaShareArn=arn)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
            ):
                raise

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=arn),
        lambda qs: qs["status"] == "VALID",
        timeout_s=90,
    )
    return arn


def _setup_real_quota_share(ctx):
    se_name = _create_service_environment(ctx)
    sp_arn = _create_scheduling_policy(ctx)
    jq_arn = _create_job_queue(ctx, se_name, sp_arn)
    return _create_quota_share(ctx, jq_arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
