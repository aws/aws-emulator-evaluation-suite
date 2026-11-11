"""list-quota-shares-invalid-filter-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-quota-shares-invalid-filter-rejected"
GROUP = "overly-permissive"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListQuotaShares with an out-of-range maxResults is rejected, not silently unfiltered."""
    batch = ctx.client("batch")
    sp_arn = _create_scheduling_policy(ctx)
    se = _create_service_environment(ctx)
    jq = _create_job_queue(ctx, se["name"], sp_arn)

    share_name = ctx.unique_name("sim2real-batch-qs-").replace("-", "_")
    created = batch.create_quota_share(
        quotaShareName=share_name,
        jobQueue=jq["name"],
        capacityLimits=[{"maxCapacity": 2, "capacityUnit": "ml.m6i.large"}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        tags={"sim2real": CHECK},
    )
    share_arn = created["quotaShareArn"]
    ctx.on_cleanup(lambda: _teardown_quota_share(ctx, share_arn))
    _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=share_arn),
        lambda d: d["status"] == "VALID",
        timeout_s=90,
    )

    # maxResults must be between 1 and 100 (per API contract); 0 is out of range.
    def _bad_list():
        batch.list_quota_shares(jobQueue=jq["name"], maxResults=0)

    code, message, request_id = _error(_bad_list)
    assert code == "ClientException", f"expected ClientException, got {code}"
    # Batch wraps this validation message with the request id of the refused call.
    expected_message = (
        "Error executing request, Exception : Max Results should be greater than or equal to 1 and "
        f"less than or equal to 100., RequestId: {request_id}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: an in-range request on the same queue succeeds and returns our share.
    ok = batch.list_quota_shares(jobQueue=jq["name"], maxResults=10)
    names = [q["quotaShareName"] for q in ok["quotaShares"]]
    assert share_name in names, f"expected {share_name} in {names}"


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message, RequestId). An unexpected success
    raises."""
    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response.get("ResponseMetadata", {}).get("RequestId"),
        )
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


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
    ctx.on_cleanup(lambda: _retry_client_error(lambda: batch.delete_scheduling_policy(arn=arn)))
    return arn


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
    _retry_client_error(lambda: batch.delete_service_environment(serviceEnvironment=name))


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
    # The queue refuses deletion while its quota share is still being removed.
    _retry_client_error(lambda: batch.delete_job_queue(jobQueue=name))
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"],
        lambda jqs: not jqs or jqs[0]["status"] == "DELETED",
        timeout_s=300,
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
