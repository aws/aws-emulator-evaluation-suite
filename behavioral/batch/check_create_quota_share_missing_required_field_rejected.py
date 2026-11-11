"""create-quota-share-missing-required-field-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-quota-share-missing-required-field-rejected"
GROUP = "overly-permissive"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateQuotaShare with an empty capacityLimits list is rejected with ClientException and
    creates no share, while a share with a capacity limit on the same queue is created."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    batch = ctx.client("batch")
    scheduling_policy_arn = _create_quota_scheduling_policy(ctx, teardown_deadline)
    service_env = _create_service_environment(ctx)
    job_queue = _create_service_job_queue(ctx, service_env["arn"], scheduling_policy_arn)
    bad_name = ctx.unique_name("sim2real-batch-qs-bad-")

    code, message, request_id = _error_code(
        lambda: batch.create_quota_share(
            quotaShareName=bad_name,
            jobQueue=job_queue["arn"],
            capacityLimits=[],
            resourceSharingConfiguration={"strategy": "RESERVE"},
            preemptionConfiguration={"inSharePreemption": "ENABLED"},
        )
    )
    assert code == "ClientException", f"expected ClientException, got {code!r}"
    # Batch embeds the call's own request id in this message.
    expected_message = (
        "Error executing request, Exception : capacityLimits is required and cannot be empty., "
        f"RequestId: {request_id}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no quota share with that name exists on the queue.
    listed = batch.list_quota_shares(jobQueue=job_queue["arn"])["quotaShares"]
    listed_names = [qs["quotaShareName"] for qs in listed]
    assert bad_name not in listed_names, (
        f"expected {bad_name!r} absent after rejected create, found it in {listed_names!r}"
    )

    # Positive control: the same call with a non-empty capacityLimits succeeds.
    good_name = ctx.unique_name("sim2real-batch-qs-good-")
    resp = batch.create_quota_share(
        quotaShareName=good_name,
        jobQueue=job_queue["arn"],
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 5}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "ENABLED"},
        tags=_MANAGED_TAGS,
    )
    good_arn = resp["quotaShareArn"]

    def _describe():
        return batch.describe_quota_share(quotaShareArn=good_arn)

    _poll_until(_describe, lambda qs: qs["status"] in ("VALID", "INVALID"), desc="quota share VALID")

    def _cleanup():
        try:
            batch.update_quota_share(quotaShareArn=good_arn, state="DISABLED")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
            ):
                raise
        batch.delete_quota_share(quotaShareArn=good_arn)

    ctx.on_cleanup(_cleanup)

    listed_after = batch.list_quota_shares(jobQueue=job_queue["arn"])["quotaShares"]
    listed_after_names = [qs["quotaShareName"] for qs in listed_after]
    assert good_name in listed_after_names, (
        f"expected {good_name!r} present after accepted create, got {listed_after_names!r}"
    )


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0, desc="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{desc} not met within {timeout_s}s (last={last!r})")


def _error_code(fn):
    """Call fn(); return its botocore Error (code, message, request id). An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal
    available and must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response["ResponseMetadata"].get("RequestId"),
        )
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_service_environment(ctx):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-se-")
    resp = batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 4}],
        state="ENABLED",
        tags=_MANAGED_TAGS,
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
        tags=_MANAGED_TAGS,
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
        tags=_MANAGED_TAGS,
    )
    arn = resp["arn"]

    def _cleanup():
        _delete_when_released(lambda: batch.delete_scheduling_policy(arn=arn), teardown_deadline)

    ctx.on_cleanup(_cleanup)
    return arn


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
