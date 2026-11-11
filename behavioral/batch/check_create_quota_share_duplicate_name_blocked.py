"""create-quota-share-duplicate-name-blocked."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-quota-share-duplicate-name-blocked"
GROUP = "overly-permissive"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateQuotaShare with a name that already exists on the same job queue is rejected."""
    batch = ctx.client("batch")
    sp_arn = _create_scheduling_policy(ctx)
    se = _create_service_environment(ctx)
    jq = _create_job_queue(ctx, se["name"], sp_arn)

    share_name = ctx.unique_name("sim2real-batch-qs-").replace("-", "_")
    capacity_limits = [{"maxCapacity": 2, "capacityUnit": "ml.m6i.large"}]
    resource_sharing = {"strategy": "RESERVE"}
    preemption = {"inSharePreemption": "DISABLED"}

    first = batch.create_quota_share(
        quotaShareName=share_name,
        jobQueue=jq["name"],
        capacityLimits=capacity_limits,
        resourceSharingConfiguration=resource_sharing,
        preemptionConfiguration=preemption,
        tags={"sim2real": CHECK},
    )
    first_arn = first["quotaShareArn"]
    ctx.on_cleanup(lambda: _teardown_quota_share(ctx, first_arn))
    _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=first_arn),
        lambda d: d["status"] == "VALID",
        timeout_s=90,
    )

    def _dup():
        batch.create_quota_share(
            quotaShareName=share_name,
            jobQueue=jq["name"],
            capacityLimits=capacity_limits,
            resourceSharingConfiguration=resource_sharing,
            preemptionConfiguration=preemption,
        )

    code, message, request_id = _error_code(_dup)
    assert code == "ClientException", f"expected ClientException, got {code}"
    expected_message = (
        f"QuotaShare with name {share_name} already exists for job queue {jq['name']}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the queue still has exactly one quota share with this name.
    listing = batch.list_quota_shares(jobQueue=jq["name"])["quotaShares"]
    matching = [q for q in listing if q["quotaShareName"] == share_name]
    assert len(matching) == 1, f"expected exactly 1 quota share named {share_name}, found {len(matching)}"
    assert matching[0]["quotaShareArn"] == first_arn, (
        f"expected the surviving quota share named {share_name} to still be {first_arn}, "
        f"got {matching[0]['quotaShareArn']}"
    )

    # Positive control: a quota share with a *different* name on the same queue succeeds.
    other_name = ctx.unique_name("sim2real-batch-qs2-").replace("-", "_")
    second = batch.create_quota_share(
        quotaShareName=other_name,
        jobQueue=jq["name"],
        capacityLimits=capacity_limits,
        resourceSharingConfiguration=resource_sharing,
        preemptionConfiguration=preemption,
        tags={"sim2real": CHECK},
    )
    second_arn = second["quotaShareArn"]
    ctx.on_cleanup(lambda: _teardown_quota_share(ctx, second_arn))

    # Independent read at the destination: the differently-named share is really
    # there under its own name, not just echoed back in the mutating response.
    described_second = batch.describe_quota_share(quotaShareArn=second_arn)
    assert described_second["quotaShareName"] == other_name, (
        f"expected describe_quota_share to report name {other_name!r}, "
        f"got {described_second['quotaShareName']!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore Error (code, message, request id). An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response["ResponseMetadata"].get("RequestId"),
        )
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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
        tags={"sim2real": CHECK},
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
        tags={"sim2real": CHECK},
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
        tags={"sim2real": CHECK},
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
    # DeleteJobQueue is asynchronous; the scheduling policy cleanup that runs next is refused
    # while the queue still references it, so wait until the queue is gone.
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"],
        lambda qs: not qs,
        timeout_s=180,
        interval_s=5,
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

    # DeleteQuotaShare is asynchronous, and DeleteJobQueue is refused while a share remains.
    def _gone():
        try:
            batch.describe_quota_share(quotaShareArn=quota_share_arn)
            return False
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
            return True

    _poll_until(_gone, lambda g: g, timeout_s=120, interval_s=5)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
