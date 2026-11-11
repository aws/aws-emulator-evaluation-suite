"""delete-quota-share-in-use-by-scheduling-policy-blocked."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-quota-share-in-use-by-scheduling-policy-blocked"
GROUP = "overly-permissive"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteQuotaShare fails while the share is still ENABLED under its owning job queue."""
    batch = ctx.client("batch")
    sp_arn = _create_scheduling_policy(ctx)
    se = _create_service_environment(ctx)
    jq = _create_job_queue(ctx, se["name"], sp_arn)

    share_name = ctx.unique_name("sim2real-batch-qs-inuse-").replace("-", "_")
    created = batch.create_quota_share(
        quotaShareName=share_name,
        jobQueue=jq["name"],
        capacityLimits=[{"maxCapacity": 2, "capacityUnit": "ml.m6i.large"}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        tags={"sim2real-check": CHECK},
    )
    share_arn = created["quotaShareArn"]
    ctx.on_cleanup(lambda: _teardown_quota_share(ctx, share_arn))
    _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=share_arn),
        lambda d: d["status"] == "VALID" and d["state"] == "ENABLED",
        timeout_s=90,
    )

    # Attempt to delete while still ENABLED/active -> must be blocked.
    def _delete_while_enabled():
        batch.delete_quota_share(quotaShareArn=share_arn)

    code, message = _expect_error(_delete_while_enabled)
    assert code == "ClientException", f"expected ClientException, got {code}"
    expected = "Quota Share must be DISABLED before deleting."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the quota share still exists and is still ENABLED.
    still_there = batch.describe_quota_share(quotaShareArn=share_arn)
    assert still_there["quotaShareName"] == share_name, (
        f"expected quota share name {share_name!r} to be unchanged, got {still_there['quotaShareName']!r}"
    )
    assert still_there["state"] == "ENABLED", (
        f"expected the rejected delete to leave state ENABLED, got {still_there['state']!r}"
    )

    # Positive control: disable it first, then deletion succeeds.
    batch.update_quota_share(quotaShareArn=share_arn, state="DISABLED")
    _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=share_arn),
        lambda d: d["state"] == "DISABLED" and d["status"] == "VALID",
        timeout_s=90,
    )
    batch.delete_quota_share(quotaShareArn=share_arn)

    def _probe_gone():
        try:
            batch.describe_quota_share(quotaShareArn=share_arn)
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")
        return "still-describable", None

    deleted_code, deleted_message = _poll_until(_probe_gone, lambda r: r[0] == "ClientException", timeout_s=90)
    assert deleted_code == "ClientException", f"expected quota share gone, got code {deleted_code}"
    expected_gone = f"{share_arn} does not exist."
    assert deleted_message == expected_gone, f"expected message {expected_gone!r}, got {deleted_message!r}"


def _expect_error(fn):
    """Call fn(); return its (Error.Code, Error.Message). An unexpected SUCCESS raises directly."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _create_scheduling_policy(ctx):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")
    arn = batch.create_scheduling_policy(
        name=name,
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags={"sim2real-check": CHECK},
    )["arn"]
    ctx.on_cleanup(lambda: batch.delete_scheduling_policy(arn=arn))
    return arn


def _create_service_environment(ctx, capacity_unit="ml.m6i.large", max_capacity=2):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-se-")
    batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"maxCapacity": max_capacity, "capacityUnit": capacity_unit}],
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _teardown_service_environment(ctx, name))
    _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0],
        lambda se: se["status"] == "VALID",
        timeout_s=90,
    )
    return {"name": name}


def _teardown_service_environment(ctx, name):
    batch = ctx.client("batch")
    try:
        batch.update_service_environment(serviceEnvironment=name, state="DISABLED")
        _poll_until(
            lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0],
            lambda se: se["state"] == "DISABLED" and se["status"] == "VALID",
            timeout_s=90,
        )
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    batch.delete_service_environment(serviceEnvironment=name)


def _create_job_queue(ctx, service_environment_name, scheduling_policy_arn, priority=1):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-jq-")
    batch.create_job_queue(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=priority,
        schedulingPolicyArn=scheduling_policy_arn,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": service_environment_name}],
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _teardown_job_queue(ctx, name))
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"][0],
        lambda jq: jq["status"] == "VALID",
        timeout_s=90,
    )
    return {"name": name}


def _teardown_job_queue(ctx, name):
    batch = ctx.client("batch")
    try:
        batch.update_job_queue(jobQueue=name, state="DISABLED")
        _poll_until(
            lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"][0],
            lambda jq: jq["state"] == "DISABLED" and jq["status"] == "VALID",
            timeout_s=90,
        )
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    batch.delete_job_queue(jobQueue=name)
    # The service environment and scheduling policy deletes that run next are refused while
    # the queue still exists, so wait for it to be gone.
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"],
        lambda queues: not queues,
        timeout_s=180,
    )


def _teardown_quota_share(ctx, quota_share_arn):
    batch = ctx.client("batch")
    try:
        batch.update_quota_share(quotaShareArn=quota_share_arn, state="DISABLED")
        _poll_until(
            lambda: batch.describe_quota_share(quotaShareArn=quota_share_arn),
            lambda d: d["state"] == "DISABLED" and d["status"] == "VALID",
            timeout_s=90,
        )
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ClientException"
            and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
        ):
            raise
    batch.delete_quota_share(quotaShareArn=quota_share_arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
