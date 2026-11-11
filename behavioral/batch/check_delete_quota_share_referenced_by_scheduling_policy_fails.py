"""delete-quota-share-referenced-by-scheduling-policy-fails."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-quota-share-referenced-by-scheduling-policy-fails"
GROUP = "overly-permissive"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteQuotaShare on a still-ENABLED quota share is rejected with ClientException instead of
    deleting an in-use share; after UpdateQuotaShare state=DISABLED the identical call succeeds."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    batch = ctx.client("batch")

    policy_arn = _create_quota_scheduling_policy(ctx, teardown_deadline)
    se_name = _create_service_environment(ctx, teardown_deadline)
    jq_name = _create_sagemaker_job_queue(ctx, se_name, teardown_deadline, scheduling_policy_arn=policy_arn)

    quota_share_name = ctx.unique_name("sim2real-batch-qs-")
    created = batch.create_quota_share(
        quotaShareName=quota_share_name,
        jobQueue=jq_name,
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 1}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        state="ENABLED",
    )
    quota_share_arn = created["quotaShareArn"]

    def _cleanup_quota_share() -> None:
        try:
            batch.update_quota_share(quotaShareArn=quota_share_arn, state="DISABLED")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
            ):
                raise
        try:
            batch.delete_quota_share(quotaShareArn=quota_share_arn)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
                raise

    ctx.on_cleanup(_cleanup_quota_share)

    described = _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=quota_share_arn),
        lambda q: q["status"] in ("VALID", "INVALID"),
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert described["status"] == "VALID", f"quota share failed to validate: {described}"
    assert described["state"] == "ENABLED", f"expected ENABLED before the negative, got {described['state']!r}"

    # Negative: deleting the still-ENABLED quota share must be rejected.
    code, message = _error(lambda: batch.delete_quota_share(quotaShareArn=quota_share_arn))
    assert code == "ClientException", (
        f"expected ClientException deleting an ENABLED quota share, got {code!r}"
    )
    expected_message = "Quota Share must be DISABLED before deleting."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The forbidden effect did not happen: the quota share is still there and
    # still ENABLED after the rejected delete attempt.
    still_there = batch.describe_quota_share(quotaShareArn=quota_share_arn)
    assert still_there["quotaShareArn"] == quota_share_arn, (
        f"expected {quota_share_arn!r} to still describe, got {still_there.get('quotaShareArn')!r}"
    )
    assert still_there["state"] == "ENABLED", (
        f"expected the rejected delete to leave state ENABLED, got {still_there['state']!r}"
    )
    assert still_there["status"] in ("VALID", "UPDATING"), (
        f"expected status VALID or UPDATING after the rejected delete, got {still_there['status']!r}"
    )

    # Positive control: once the precondition (state=DISABLED) is satisfied, the
    # identical DeleteQuotaShare call succeeds.
    batch.update_quota_share(quotaShareArn=quota_share_arn, state="DISABLED")
    disabled = _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=quota_share_arn),
        lambda q: q["state"] == "DISABLED" and q["status"] in ("VALID", "INVALID"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert disabled["state"] == "DISABLED", f"expected DISABLED after update, got {disabled['state']!r}"

    batch.delete_quota_share(quotaShareArn=quota_share_arn)

    gone = _poll_until(
        lambda: _describe_quota_share_or_none(batch, quota_share_arn),
        lambda q: q is None,
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert gone is None, f"expected the disabled quota share to be fully deleted, got {gone!r}"

    # A mutation on the dead id also fails, via an independent operation.
    dead_code, dead_message = _error(
        lambda: batch.update_quota_share(quotaShareArn=quota_share_arn, state="ENABLED")
    )
    assert dead_code == "ClientException", (
        f"expected ClientException updating a deleted quota share, got {dead_code!r}"
    )
    expected_dead_message = f"{quota_share_arn} does not exist."
    assert dead_message == expected_dead_message, (
        f"expected message {expected_dead_message!r}, got {dead_message!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but call succeeded and returned {result!r}")


def _describe_quota_share_or_none(batch, arn: str) -> Any:
    try:
        return batch.describe_quota_share(quotaShareArn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ClientException":
            return None
        raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 120.0, interval_s: float = 3.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_quota_scheduling_policy(ctx, teardown_deadline) -> str:
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")
    created = batch.create_scheduling_policy(
        name=name,
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
    )
    arn = created["arn"]

    def _cleanup() -> None:
        _delete_when_released(lambda: batch.delete_scheduling_policy(arn=arn), teardown_deadline)

    ctx.on_cleanup(_cleanup)
    return arn


def _create_service_environment(ctx, teardown_deadline) -> str:
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-se-")
    batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 1}],
    )

    def _cleanup() -> None:
        try:
            batch.update_service_environment(serviceEnvironment=name, state="DISABLED")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
        _await_disabled(
            lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"],
            teardown_deadline,
        )
        _delete_when_released(lambda: batch.delete_service_environment(serviceEnvironment=name), teardown_deadline)
        _await_gone(
            lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"],
            teardown_deadline,
        )

    ctx.on_cleanup(_cleanup)

    _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"],
        lambda envs: bool(envs) and envs[0]["status"] in ("VALID", "INVALID"),
        timeout_s=120.0,
        interval_s=3.0,
    )
    final = batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0]
    assert final["status"] == "VALID", f"service environment failed to validate: {final}"
    return name


def _create_sagemaker_job_queue(
    ctx, service_environment_name: str, teardown_deadline, scheduling_policy_arn: str | None = None
) -> str:
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-jq-")
    kwargs: dict[str, Any] = dict(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": service_environment_name}],
    )
    if scheduling_policy_arn:
        kwargs["schedulingPolicyArn"] = scheduling_policy_arn
    batch.create_job_queue(**kwargs)

    def _cleanup() -> None:
        try:
            batch.update_job_queue(jobQueue=name, state="DISABLED")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
        _await_disabled(lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"], teardown_deadline)
        _delete_when_released(lambda: batch.delete_job_queue(jobQueue=name), teardown_deadline)
        _await_gone(lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"], teardown_deadline)

    ctx.on_cleanup(_cleanup)

    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"],
        lambda qs: bool(qs) and qs[0]["status"] in ("VALID", "INVALID"),
        timeout_s=120.0,
        interval_s=3.0,
    )
    final = batch.describe_job_queues(jobQueues=[name])["jobQueues"][0]
    assert final["status"] == "VALID", f"job queue failed to validate: {final}"
    return name


# The batch suite's 600 s cleanup budget less a margin, one deadline shared by every teardown of a run.
_TEARDOWN_RETRY_S = 540.0


def _teardown_until(teardown_deadline) -> float:
    """The run's one teardown deadline, started by the first teardown that asks for it."""
    return teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S)


def _await_disabled(describe, teardown_deadline) -> None:
    """Poll a Batch describe every 2 s until the resource is DISABLED and not UPDATING (or is
    absent), raising at the shared deadline: Batch deletes only a disabled, settled resource."""
    deadline = _teardown_until(teardown_deadline)
    while True:
        found = describe()
        if not found or (found[0]["state"] == "DISABLED" and found[0].get("status") != "UPDATING"):
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"not DISABLED at the teardown deadline: {found[0]!r}")
        time.sleep(2)


def _await_gone(describe, teardown_deadline) -> None:
    """Poll a Batch describe every 2 s until the resource is gone (absent or DELETED), raising at
    the shared deadline: a still-DELETING queue blocks deleting its environment and policy."""
    deadline = _teardown_until(teardown_deadline)
    while True:
        found = describe()
        if not found or found[0].get("status") == "DELETED":
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"still present at the teardown deadline: {found[0]!r}")
        time.sleep(2)


def _delete_when_released(call, teardown_deadline) -> None:
    """Run a Batch delete; while Batch refuses it with "Cannot delete, found existing ..."
    (a dependent still deleting) or "Cannot delete, resource is being modified" (a state update
    still settling), retry every 2 s to the shared deadline; raise everything else."""
    deadline = _teardown_until(teardown_deadline)
    while True:
        try:
            call()
            return
        except ClientError as exc:
            err = exc.response["Error"]
            in_use = err["Code"] == "ClientException" and err.get("Message", "").startswith(
                ("Cannot delete, found existing", "Cannot delete, resource is being modified")
            )
            if not in_use or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
