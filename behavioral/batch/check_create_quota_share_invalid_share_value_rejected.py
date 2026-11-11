"""create-quota-share-invalid-share-value-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-quota-share-invalid-share-value-rejected"
GROUP = "overly-permissive"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateQuotaShare with a negative capacity value is rejected, not silently clamped."""
    batch = ctx.client("batch")
    sp_arn = _create_scheduling_policy(ctx)
    se = _create_service_environment(ctx)
    jq = _create_job_queue(ctx, se["name"], sp_arn)

    bad_name = ctx.unique_name("sim2real-batch-qs-bad-").replace("-", "_")

    def _bad_create():
        batch.create_quota_share(
            quotaShareName=bad_name,
            jobQueue=jq["name"],
            capacityLimits=[{"maxCapacity": -5, "capacityUnit": "ml.m6i.large"}],
            resourceSharingConfiguration={"strategy": "RESERVE"},
            preemptionConfiguration={"inSharePreemption": "DISABLED"},
        )

    code, message, request_id = _error_code(_bad_create)
    assert code == "ClientException", f"expected ClientException, got {code}"
    # Batch embeds the call's own request id in this message.
    expected_message = (
        "Error executing request, Exception : maxCapacity must be greater than 0., "
        f"RequestId: {request_id}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no quota share with the malformed name was created on the queue.
    listing = batch.list_quota_shares(jobQueue=jq["name"])["quotaShares"]
    assert not any(q["quotaShareName"] == bad_name for q in listing), (
        "a quota share was created despite a negative maxCapacity"
    )

    # Positive control: the same shape of request with a valid maxCapacity succeeds.
    good_name = ctx.unique_name("sim2real-batch-qs-good-").replace("-", "_")
    good = batch.create_quota_share(
        quotaShareName=good_name,
        jobQueue=jq["name"],
        capacityLimits=[{"maxCapacity": 2, "capacityUnit": "ml.m6i.large"}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        tags={"sim2real": "create-quota-share-invalid-share-value-rejected"},
    )
    ctx.on_cleanup(lambda: _teardown_quota_share(ctx, good["quotaShareArn"]))
    described = _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=good["quotaShareArn"]),
        lambda d: d["status"] == "VALID",
        timeout_s=90,
    )
    got_capacity = described["capacityLimits"][0]["maxCapacity"]
    assert got_capacity == 2, f"expected maxCapacity 2 on the valid quota share, got {got_capacity}"


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
        tags={"sim2real": "create-quota-share-invalid-share-value-rejected"},
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
        tags={"sim2real": "create-quota-share-invalid-share-value-rejected"},
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
        tags={"sim2real": "create-quota-share-invalid-share-value-rejected"},
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
