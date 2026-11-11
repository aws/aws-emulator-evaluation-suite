"""update-quota-share-negative-amount-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-quota-share-negative-amount-rejected"
GROUP = "overly-permissive"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateQuotaShare with a negative maxCapacity in capacityLimits is rejected with
    ClientException rather than silently accepted (which would corrupt the scheduler's
    capacity accounting).
    """
    batch = ctx.client("batch")
    scheduling_policy_arn = _create_quota_scheduling_policy(ctx)
    service_env = _create_service_environment(ctx)
    job_queue = _create_service_job_queue(ctx, service_env["arn"], scheduling_policy_arn)
    quota_share = _create_quota_share(ctx, job_queue["arn"], max_capacity=10)

    # Break exactly one thing: a negative maxCapacity.
    response = _error_response(
        lambda: batch.update_quota_share(
            quotaShareArn=quota_share["arn"],
            capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": -5}],
        )
    )
    code, message = response["Error"].get("Code"), response["Error"].get("Message")
    assert code == "ClientException", f"expected ClientException, got {code!r}"
    # The message embeds the request id of this very call.
    request_id = response["ResponseMetadata"]["RequestId"]
    expected = f"Error executing request, Exception : maxCapacity must be greater than 0., RequestId: {request_id}"
    assert message == expected, f"expected the exact negative-maxCapacity message {expected!r}, got {message!r}"

    # Effect absent: capacityLimits must remain at the original value.
    unchanged = batch.describe_quota_share(quotaShareArn=quota_share["arn"])
    assert unchanged["capacityLimits"] == [{"capacityUnit": "ml.m5.large", "maxCapacity": 10}], unchanged[
        "capacityLimits"
    ]

    # Positive control: a valid, non-negative update is accepted and persists.
    batch.update_quota_share(
        quotaShareArn=quota_share["arn"],
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 20}],
    )
    updated = _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=quota_share["arn"]),
        lambda qs: qs["status"] in ("VALID", "INVALID"),
        timeout_s=90,
        interval_s=3,
        desc="quota share update settled",
    )
    assert updated["capacityLimits"] == [{"capacityUnit": "ml.m5.large", "maxCapacity": 20}], updated[
        "capacityLimits"
    ]


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0, desc="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{desc} not met within {timeout_s}s (last={last!r})")


def _error_response(fn):
    """Call fn(); return its botocore error response. An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_service_environment(ctx):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-se-")
    resp = batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 4}],
        state="ENABLED",
        tags={"sim2real": CHECK},
    )
    arn = resp["serviceEnvironmentArn"]

    def _describe():
        return batch.describe_service_environments(serviceEnvironments=[arn])["serviceEnvironments"][0]

    _poll_until(_describe, lambda se: se["status"] in ("VALID", "INVALID"), desc="service environment VALID")

    def _cleanup():
        try:
            batch.update_service_environment(serviceEnvironment=arn, state="DISABLED")
            _poll_until(_describe, lambda se: se["state"] == "DISABLED", timeout_s=60, desc="SE disabled")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
        _poll_until(
            lambda: _try_delete(lambda: batch.delete_service_environment(serviceEnvironment=arn)),
            lambda ok: ok,
            timeout_s=90,
            desc="service environment deleted",
        )

    ctx.on_cleanup(_cleanup)
    return {"name": name, "arn": arn}


def _create_service_job_queue(ctx, service_env_arn, scheduling_policy_arn):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sjq-")
    resp = batch.create_job_queue(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        state="ENABLED",
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": service_env_arn}],
        schedulingPolicyArn=scheduling_policy_arn,
        tags={"sim2real": CHECK},
    )
    arn = resp["jobQueueArn"]

    def _describe():
        return batch.describe_job_queues(jobQueues=[arn])["jobQueues"][0]

    _poll_until(_describe, lambda jq: jq["status"] in ("VALID", "INVALID"), desc="job queue VALID")

    def _cleanup():
        try:
            batch.update_job_queue(jobQueue=arn, state="DISABLED")
            _poll_until(_describe, lambda jq: jq["state"] == "DISABLED", timeout_s=60, desc="JQ disabled")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
        _poll_until(
            lambda: _try_delete(lambda: batch.delete_job_queue(jobQueue=arn)),
            lambda ok: ok,
            timeout_s=90,
            desc="job queue deleted",
        )

    ctx.on_cleanup(_cleanup)
    return {"name": name, "arn": arn}


def _create_quota_scheduling_policy(ctx):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")
    resp = batch.create_scheduling_policy(
        name=name,
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags={"sim2real": CHECK},
    )
    arn = resp["arn"]

    def _cleanup():
        batch.delete_scheduling_policy(arn=arn)

    ctx.on_cleanup(_cleanup)
    return arn


def _create_quota_share(ctx, job_queue_arn, *, max_capacity=10, state="ENABLED"):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-qs-")
    resp = batch.create_quota_share(
        quotaShareName=name,
        jobQueue=job_queue_arn,
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": max_capacity}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "ENABLED"},
        state=state,
        tags={"sim2real": CHECK},
    )
    arn = resp["quotaShareArn"]

    def _describe():
        return batch.describe_quota_share(quotaShareArn=arn)

    _poll_until(_describe, lambda qs: qs["status"] in ("VALID", "INVALID"), desc="quota share VALID")

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
        batch.delete_quota_share(quotaShareArn=arn)

    ctx.on_cleanup(_cleanup)
    return {"name": name, "arn": arn}


def _try_delete(fn):
    try:
        fn()
        return True
    except ClientError:
        return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
