"""delete-quota-share-in-use-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-quota-share-in-use-rejected"
GROUP = "overly-permissive"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteQuotaShare on an ENABLED quota share is rejected with ClientException and leaves it
    ENABLED and listed; after UpdateQuotaShare sets it DISABLED, the same delete removes it."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    batch = ctx.client("batch")
    scheduling_policy_arn = _create_quota_scheduling_policy(ctx, teardown_deadline)
    service_env = _create_service_environment(ctx)
    job_queue = _create_service_job_queue(ctx, service_env["arn"], scheduling_policy_arn)
    quota_share = _create_quota_share(ctx, job_queue["arn"], state="ENABLED")

    # Break exactly one thing: try to delete while still ENABLED / in use.
    code, message = _expect_client_error(lambda: batch.delete_quota_share(quotaShareArn=quota_share["arn"]))
    assert code == "ClientException", f"expected ClientException, got {code!r}"
    expected = "Quota Share must be DISABLED before deleting."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the quota share must still exist, unchanged -- checked via two
    # independent reads, neither of which is the mutating DeleteQuotaShare call.
    still_there = batch.describe_quota_share(quotaShareArn=quota_share["arn"])
    assert still_there["quotaShareArn"] == quota_share["arn"], (
        f"expected the rejected delete to leave arn {quota_share['arn']!r} in place, "
        f"got {still_there['quotaShareArn']!r}"
    )
    assert still_there["state"] == "ENABLED", (
        f"expected the rejected delete to leave state 'ENABLED', got {still_there['state']!r}"
    )
    listed = [
        qs["quotaShareArn"]
        for qs in batch.list_quota_shares(jobQueue=job_queue["arn"])["quotaShares"]
    ]
    assert quota_share["arn"] in listed, (
        f"expected {quota_share['arn']!r} to still be listed on its job queue after the "
        f"rejected delete, got {listed!r}"
    )

    # Positive control: disable first, then delete succeeds.
    batch.update_quota_share(quotaShareArn=quota_share["arn"], state="DISABLED")
    _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=quota_share["arn"]),
        lambda qs: qs["state"] == "DISABLED" and qs["status"] in ("VALID", "INVALID"),
        timeout_s=90,
        interval_s=3,
        desc="quota share DISABLED",
    )
    batch.delete_quota_share(quotaShareArn=quota_share["arn"])
    def _probe_gone():
        try:
            batch.describe_quota_share(quotaShareArn=quota_share["arn"])
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message")
        return "still-describable", None

    _, gone_message = _poll_until(
        _probe_gone,
        lambda r: r[0] == "ClientException",
        timeout_s=90,
        interval_s=3,
        desc="quota share deleted",
    )
    expected_gone = f"{quota_share['arn']} does not exist."
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0, desc="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{desc} not met within {timeout_s}s (last={last!r})")


def _expect_client_error(fn):
    """Call fn(); return its (Error.Code, Error.Message). An unexpected SUCCESS raises instead of
    returning a falsy sentinel -- an over-permissive target must not turn acceptance into a
    code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


def _create_service_environment(ctx):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-se-")
    resp = batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 4}],
        state="ENABLED",
        tags={"sim2real": "true"},
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
        tags={"sim2real": "true"},
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


def _create_quota_scheduling_policy(ctx, teardown_deadline):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")
    resp = batch.create_scheduling_policy(
        name=name,
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags={"sim2real": "true"},
    )
    arn = resp["arn"]

    def _cleanup():
        _delete_when_released(lambda: batch.delete_scheduling_policy(arn=arn), teardown_deadline)

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
        tags={"sim2real": "true"},
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


# The batch suite's cleanup budget (900 s), one deadline shared by every teardown of a run.
_TEARDOWN_RETRY_S = 900.0


def _delete_when_released(call, teardown_deadline) -> None:
    """Run a Batch delete; while Batch refuses it with "Cannot delete, found existing ..."
    (a dependent still deleting), retry every 2 s to the shared deadline; raise everything else."""
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 120.0)
    while True:
        try:
            call()
            return
        except ClientError as exc:
            err = exc.response["Error"]
            in_use = err["Code"] == "ClientException" and err.get("Message", "").startswith(
                "Cannot delete, found existing"
            )
            if not in_use or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
