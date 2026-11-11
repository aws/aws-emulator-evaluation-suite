"""concurrent-quota-share-updates-optimistic-lock."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-quota-share-updates-optimistic-lock"
GROUP = "concurrency"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateQuotaShare calls with different capacityLimits persist exactly one of
    the two values, never a merge; a rejected racer fails with ClientException and the final
    value is the other racer's."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    batch = ctx.client("batch")

    senv_name = _create_service_environment(ctx, teardown_deadline)
    sp_arn = _create_scheduling_policy(ctx, teardown_deadline)
    jq_name = _create_job_queue(ctx, senv_name, sp_arn, teardown_deadline)
    qs_arn = _create_quota_share(ctx, jq_name, max_capacity=5)

    barrier = threading.Barrier(2)

    def _race_update(max_capacity: int):
        barrier.wait()
        try:
            batch.update_quota_share(
                quotaShareArn=qs_arn,
                capacityLimits=[{"capacityUnit": "ml.m6i.large", "maxCapacity": max_capacity}],
            )
            return (max_capacity, None)
        except ClientError as err:
            return (max_capacity, err.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_race_update, 111), pool.submit(_race_update, 222)]
        results = [f.result(timeout=60) for f in futures]

    raced_values = {111, 222}
    successes = [r for r in results if r[1] is None]
    failures = [r for r in results if r[1] is not None]

    # Empirically, AWS Batch's UpdateQuotaShare does not reject the "loser" of a race with a
    # version-conflict error -- both concurrent callers can get a 200. What must never happen is
    # a lost-update anomaly that corrupts the share into a state that isn't one of the two raced
    # values. If a rejection ever does occur, it must be the well-defined ClientException.
    assert len(successes) >= 1, f"expected at least one racer to succeed, got {results}"
    for _, code in failures:
        assert code == "ClientException", f"unexpected rejection code for a losing racer: {code!r}"

    final = _wait_for(
        lambda: batch.describe_quota_share(quotaShareArn=qs_arn),
        lambda d: d["status"] == "VALID",
    )
    final_limits = final["capacityLimits"]
    assert len(final_limits) == 1, f"expected a single, non-merged capacityLimits entry, got {final_limits!r}"
    final_capacity = final_limits[0]["maxCapacity"]
    assert final_capacity in raced_values, (
        f"final capacityLimits {final_capacity!r} must be exactly one of the raced values {raced_values}, "
        "not a merged/corrupted composite"
    )
    succeeded_values = {v for v, _ in successes}
    assert final_capacity in succeeded_values, (
        f"final persisted value {final_capacity} must match one of the racers that actually succeeded "
        f"({succeeded_values}), got results={results}"
    )


def _wait_for(probe, predicate, *, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_service_environment(ctx, teardown_deadline, capacity_unit="ml.m6i.large", max_capacity=10):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-senv-")
    batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": capacity_unit, "maxCapacity": max_capacity}],
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_service_environment(ctx, name, teardown_deadline))
    _wait_for(
        lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0],
        lambda se: se["status"] == "VALID",
    )
    return name


def _delete_service_environment(ctx, name, teardown_deadline):
    batch = ctx.client("batch")
    try:
        batch.update_service_environment(serviceEnvironment=name, state="DISABLED")
        _wait_for(
            lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0],
            lambda se: se["status"] == "VALID" and se["state"] == "DISABLED",
            timeout_s=60,
        )
        _delete_when_released(lambda: batch.delete_service_environment(serviceEnvironment=name), teardown_deadline)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


def _create_scheduling_policy(ctx, teardown_deadline):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")
    created = batch.create_scheduling_policy(
        name=name,
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags=_MANAGED_TAGS,
    )
    arn = created["arn"]
    ctx.on_cleanup(lambda: _delete_scheduling_policy_best_effort(ctx, arn, teardown_deadline))
    return arn


def _delete_scheduling_policy_best_effort(ctx, arn, teardown_deadline):
    batch = ctx.client("batch")
    _delete_when_released(lambda: batch.delete_scheduling_policy(arn=arn), teardown_deadline)


def _create_job_queue(ctx, service_env_name, scheduling_policy_arn, teardown_deadline):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-jq-")
    batch.create_job_queue(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": service_env_name}],
        schedulingPolicyArn=scheduling_policy_arn,
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_job_queue(ctx, name, teardown_deadline))
    _wait_for(
        lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"][0],
        lambda jq: jq["status"] == "VALID",
    )
    return name


def _delete_job_queue(ctx, name, teardown_deadline):
    batch = ctx.client("batch")
    try:
        batch.update_job_queue(jobQueue=name, state="DISABLED")
        _wait_for(
            lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"][0],
            lambda jq: jq["status"] == "VALID" and jq["state"] == "DISABLED",
            timeout_s=60,
        )
        _delete_when_released(lambda: batch.delete_job_queue(jobQueue=name), teardown_deadline)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


def _create_quota_share(ctx, jq_name, max_capacity=5):
    batch = ctx.client("batch")
    qs_name = ctx.unique_name("sim2real-batch-qs-")
    created = batch.create_quota_share(
        quotaShareName=qs_name,
        jobQueue=jq_name,
        capacityLimits=[{"capacityUnit": "ml.m6i.large", "maxCapacity": max_capacity}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        tags=_MANAGED_TAGS,
    )
    qs_arn = created["quotaShareArn"]
    ctx.on_cleanup(lambda: _delete_quota_share_best_effort(ctx, qs_arn))
    _wait_for(
        lambda: batch.describe_quota_share(quotaShareArn=qs_arn),
        lambda d: d["status"] == "VALID",
    )
    return qs_arn


def _delete_quota_share_best_effort(ctx, arn):
    batch = ctx.client("batch")
    try:
        batch.update_quota_share(quotaShareArn=arn, state="DISABLED")
        _wait_for(
            lambda: batch.describe_quota_share(quotaShareArn=arn),
            lambda d: d["status"] == "VALID" and d["state"] == "DISABLED",
            timeout_s=60,
        )
        batch.delete_quota_share(quotaShareArn=arn)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ClientException"
            and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
        ):
            raise


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
