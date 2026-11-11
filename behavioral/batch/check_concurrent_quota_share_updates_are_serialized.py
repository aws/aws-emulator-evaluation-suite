"""concurrent-quota-share-updates-are-serialized."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-quota-share-updates-are-serialized"
GROUP = "concurrency"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Parallel UpdateQuotaShare calls on one quota share settle to a single capacityLimits value
    from an accepted racer, never a merge; any rejected racer fails with ClientException, and the
    share returns to VALID."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    from botocore.exceptions import ClientError

    batch = ctx.client("batch")

    policy_arn = _create_quota_scheduling_policy(ctx, teardown_deadline)
    se_arn = _create_quota_management_service_environment(ctx, teardown_deadline)
    jq_arn = _create_quota_management_job_queue(ctx, se_arn, policy_arn, teardown_deadline)
    qs_arn = _create_quota_share(ctx, jq_arn)

    racer_values = [100 + i for i in range(5)]

    def _update(value: int):
        try:
            batch.update_quota_share(
                quotaShareArn=qs_arn,
                capacityLimits=[{"maxCapacity": value, "capacityUnit": "ml.m5.large"}],
            )
            return (value, True, None)
        except ClientError as err:
            return (value, False, err.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=len(racer_values)) as pool:
        futures = [pool.submit(_update, value) for value in racer_values]
        results = [future.result() for future in futures]

    succeeded = [value for value, ok, _code in results if ok]
    failed = [(value, code) for value, ok, code in results if not ok]

    # AWS Batch may serialize concurrent UpdateQuotaShare calls by accepting exactly one
    # writer and rejecting the rest as a write-write conflict -- but at least one racer
    # must make progress, and any rejection must be the documented conflict error, never
    # a silent drop or a corrupted partial merge.
    assert succeeded, f"no racer succeeded at all; results={results}"
    for value, code in failed:
        assert code == "ClientException", (
            f"racer maxCapacity={value} failed with unexpected error code {code!r} "
            f"(expected ClientException for a lost write-write race)"
        )
        # AWS may accept every racer; if one is rejected, only the error code is asserted,
        # not the message.

    final = _poll_quota_share_status(ctx, qs_arn, {"VALID"})
    final_limits = final["capacityLimits"]
    assert len(final_limits) == 1, f"expected exactly one capacity limit, got {final_limits}"
    assert final_limits[0]["capacityUnit"] == "ml.m5.large", (
        f"expected capacityUnit ml.m5.large, got {final_limits[0]['capacityUnit']!r}"
    )
    final_value = final_limits[0]["maxCapacity"]
    assert final_value in succeeded, (
        f"final maxCapacity {final_value} is not one of the racers Batch itself reported "
        f"as accepted ({succeeded}) -- update was lost or corrupted"
    )

    # Overly-permissive check: a quota share must be DISABLED before it can be
    # deleted, exactly like job queues and service environments. Deleting it while
    # still ENABLED (its current state after the racing updates above) must be
    # rejected -- an emulator that allows this is overly permissive.
    try:
        batch.delete_quota_share(quotaShareArn=qs_arn)
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message")
        assert code == "ClientException", (
            f"expected ClientException deleting an ENABLED quota share, got {code}"
        )
        expected_message = "Quota Share must be DISABLED before deleting."
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    else:
        raise AssertionError(
            "delete_quota_share on an ENABLED quota share unexpectedly succeeded"
        )

    # Effect absent: the rejected delete must not have touched the quota share -- it is
    # still there, still ENABLED, via an independent read.
    still_there = batch.describe_quota_share(quotaShareArn=qs_arn)
    assert still_there["state"] == "ENABLED", (
        f"rejected delete must not change state, expected ENABLED got {still_there['state']!r}"
    )
    assert still_there["status"] == "VALID", (
        f"rejected delete must not change status, expected VALID got {still_there['status']!r}"
    )


def _create_quota_scheduling_policy(ctx, teardown_deadline) -> str:
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-qmsp-")
    arn = batch.create_scheduling_policy(
        name=name,
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags={"sim2real": "true"},
    )["arn"]
    ctx.on_cleanup(lambda: _delete_when_released(lambda: batch.delete_scheduling_policy(arn=arn), teardown_deadline))
    return arn


def _create_quota_management_service_environment(ctx, teardown_deadline) -> str:
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-qmse-")
    arn = batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"maxCapacity": 10, "capacityUnit": "ml.m5.large"}],
        state="ENABLED",
        tags={"sim2real": "true"},
    )["serviceEnvironmentArn"]
    _poll_service_environment_status(ctx, arn, {"VALID"})
    ctx.on_cleanup(lambda: _disable_and_delete_service_environment(ctx, arn, teardown_deadline))
    return arn


def _create_quota_management_job_queue(ctx, se_arn: str, policy_arn: str, teardown_deadline) -> str:
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-qmjq-")
    arn = batch.create_job_queue(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        state="ENABLED",
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": se_arn}],
        schedulingPolicyArn=policy_arn,
        tags={"sim2real": "true"},
    )["jobQueueArn"]
    _poll_job_queue_status(ctx, arn, {"VALID"})
    ctx.on_cleanup(lambda: _disable_and_delete_job_queue(ctx, arn, teardown_deadline))
    return arn


def _create_quota_share(ctx, jq_arn: str) -> str:
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-qs-")
    arn = batch.create_quota_share(
        quotaShareName=name,
        jobQueue=jq_arn,
        capacityLimits=[{"maxCapacity": 1, "capacityUnit": "ml.m5.large"}],
        resourceSharingConfiguration={"strategy": "LEND_AND_BORROW", "borrowLimit": 100},
        preemptionConfiguration={"inSharePreemption": "ENABLED"},
        state="ENABLED",
        tags={"sim2real": "true"},
    )["quotaShareArn"]
    _poll_quota_share_status(ctx, arn, {"VALID"})
    ctx.on_cleanup(lambda: _disable_and_delete_quota_share(ctx, arn))
    return arn


def _poll_service_environment_status(ctx, arn: str, ok_statuses, timeout_s: float = 180.0, interval_s: float = 3.0):
    batch = ctx.client("batch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = batch.describe_service_environments(serviceEnvironments=[arn])
        envs = resp.get("serviceEnvironments", [])
        if envs:
            last = envs[0]
            if last["status"] in ok_statuses:
                return last
            if last["status"] == "INVALID":
                raise AssertionError(f"service environment went INVALID: {last}")
        time.sleep(interval_s)
    raise AssertionError(f"service environment never reached {ok_statuses}, last={last}")


def _poll_job_queue_status(ctx, arn: str, ok_statuses, timeout_s: float = 180.0, interval_s: float = 3.0):
    batch = ctx.client("batch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = batch.describe_job_queues(jobQueues=[arn])
        queues = resp.get("jobQueues", [])
        if queues:
            last = queues[0]
            if last["status"] in ok_statuses:
                return last
            if last["status"] == "INVALID":
                raise AssertionError(f"job queue went INVALID: {last}")
        time.sleep(interval_s)
    raise AssertionError(f"job queue never reached {ok_statuses}, last={last}")


def _poll_quota_share_status(ctx, arn: str, ok_statuses, timeout_s: float = 180.0, interval_s: float = 3.0):
    batch = ctx.client("batch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = batch.describe_quota_share(quotaShareArn=arn)
        if last["status"] in ok_statuses:
            return last
        if last["status"] == "INVALID":
            raise AssertionError(f"quota share went INVALID: {last}")
        time.sleep(interval_s)
    raise AssertionError(f"quota share never reached {ok_statuses}, last={last}")


def _wait_gone(is_gone, what: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    """Deletes here are asynchronous, and the next teardown is refused while this object
    still exists, so wait (bounded) until it is gone."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if is_gone():
            return
        time.sleep(interval_s)
    raise AssertionError(f"{what} still present {timeout_s}s after its delete")


def _disable_and_delete_quota_share(ctx, arn: str) -> None:
    from botocore.exceptions import ClientError

    batch = ctx.client("batch")
    batch.update_quota_share(quotaShareArn=arn, state="DISABLED")
    _wait_gone(
        lambda: batch.describe_quota_share(quotaShareArn=arn)["state"] == "DISABLED",
        f"quota share {arn} ENABLED",
    )
    _poll_quota_share_status(ctx, arn, {"VALID"})
    batch.delete_quota_share(quotaShareArn=arn)

    def _gone():
        try:
            batch.describe_quota_share(quotaShareArn=arn)
            return False
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
            return True

    _wait_gone(_gone, f"quota share {arn}")


def _disable_and_delete_job_queue(ctx, arn: str, teardown_deadline) -> None:
    batch = ctx.client("batch")
    batch.update_job_queue(jobQueue=arn, state="DISABLED")
    _poll_job_queue_status(ctx, arn, {"VALID"})
    _delete_when_released(lambda: batch.delete_job_queue(jobQueue=arn), teardown_deadline)
    _wait_gone(
        lambda: not batch.describe_job_queues(jobQueues=[arn])["jobQueues"],
        f"job queue {arn}",
    )


def _disable_and_delete_service_environment(ctx, arn: str, teardown_deadline) -> None:
    batch = ctx.client("batch")
    batch.update_service_environment(serviceEnvironment=arn, state="DISABLED")
    _poll_service_environment_status(ctx, arn, {"VALID"})
    _delete_when_released(lambda: batch.delete_service_environment(serviceEnvironment=arn), teardown_deadline)


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
