"""delete-quota-share-referenced-by-active-scheduling-policy-fails."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-quota-share-referenced-by-active-scheduling-policy-fails"
GROUP = "overly-permissive"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteQuotaShare is rejected while the quota share is still ENABLED (i.e. still
    actively part of its job queue's scheduling policy); disabling it first is required."""
    batch = ctx.client("batch")
    se_name = _create_service_environment(ctx)
    sp_arn = _create_scheduling_policy(ctx)
    jq_arn, _jq_name = _create_job_queue(ctx, se_name, scheduling_policy_arn=sp_arn)
    qs_arn, _qs_name = _create_quota_share(ctx, jq_arn, max_capacity=1)  # created ENABLED by default

    described = batch.describe_quota_share(quotaShareArn=qs_arn)
    assert described["state"] == "ENABLED", f"expected freshly-created quota share ENABLED, got {described['state']!r}"

    code, message = _expect_rejected(lambda: batch.delete_quota_share(quotaShareArn=qs_arn))
    assert code == "ClientException", f"expected ClientException, got {code}"
    expected = "Quota Share must be DISABLED before deleting."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the quota share still exists, still enabled, still listed on its queue
    still_there = batch.describe_quota_share(quotaShareArn=qs_arn)
    assert still_there["state"] == "ENABLED", (
        f"rejected delete must leave the quota share ENABLED, got {still_there['state']!r}"
    )
    assert any(
        s["quotaShareArn"] == qs_arn for s in batch.list_quota_shares(jobQueue=jq_arn)["quotaShares"]
    ), "quota share must still be listed on the job queue after the rejected delete"

    # positive control: disabling first allows the delete to succeed
    batch.update_quota_share(quotaShareArn=qs_arn, state="DISABLED")
    _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=qs_arn),
        lambda qs: qs["state"] == "DISABLED",
        timeout_s=90,
    )
    batch.delete_quota_share(quotaShareArn=qs_arn)
    def _probe_gone():
        try:
            batch.describe_quota_share(quotaShareArn=qs_arn)
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message")
        return "still-describable", None

    deleted_code, deleted_message = _poll_until(
        _probe_gone,
        lambda r: r[0] != "still-describable",
        timeout_s=90,
    )
    assert deleted_code == "ClientException", f"expected the deleted quota share's describe to fail with ClientException, got {deleted_code}"
    expected_gone = f"{qs_arn} does not exist."
    assert deleted_message == expected_gone, f"expected message {expected_gone!r}, got {deleted_message!r}"

    # a mutation on the now-dead id must also fail, not just the read
    mutate_code, mutate_message = _expect_rejected(lambda: batch.update_quota_share(quotaShareArn=qs_arn, state="ENABLED"))
    assert mutate_code == "ClientException", (
        f"expected UpdateQuotaShare on a deleted quota share to fail with ClientException, got {mutate_code}"
    )
    assert mutate_message == expected_gone, f"expected message {expected_gone!r}, got {mutate_message!r}"


from botocore.exceptions import ClientError


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _expect_rejected(fn):
    """Call fn(); return the ClientError (code, message). Raises on unexpected SUCCESS."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call succeeded and returned {result!r}")


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


def _create_scheduling_policy(ctx, with_quota_share_policy=True):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")
    kwargs = {"name": name, "tags": _MANAGED_TAGS}
    if with_quota_share_policy:
        kwargs["quotaSharePolicy"] = {"idleResourceAssignmentStrategy": "FIFO"}
    resp = batch.create_scheduling_policy(**kwargs)
    arn = resp["arn"]

    def _cleanup():
        batch.delete_scheduling_policy(arn=arn)

    ctx.on_cleanup(_cleanup)
    return arn


def _create_job_queue(ctx, service_environment_name, scheduling_policy_arn=None, priority=1):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-jq-")
    kwargs = dict(
        jobQueueName=name,
        priority=priority,
        jobQueueType="SAGEMAKER_TRAINING",
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": service_environment_name}],
        tags=_MANAGED_TAGS,
    )
    if scheduling_policy_arn:
        kwargs["schedulingPolicyArn"] = scheduling_policy_arn
    resp = batch.create_job_queue(**kwargs)
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
    return arn, name


def _create_quota_share(ctx, job_queue_arn, quota_share_name=None, max_capacity=1, capacity_unit="ml.m6i.large"):
    batch = ctx.client("batch")
    name = quota_share_name or ctx.unique_name("sim2real-batch-qs-")
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
    return arn, name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
