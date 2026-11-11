"""delete-quota-share-referenced-by-active-policy-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-quota-share-referenced-by-active-policy-fails"
GROUP = "overly-permissive"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteQuotaShare on an ENABLED quota share is rejected with ClientException, and after
    disabling it the same delete succeeds."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    batch = ctx.client("batch")
    setup = _create_quota_share_job_queue(ctx, teardown_deadline)

    qs_name = ctx.unique_name("sim2real-batch-qs-")
    qs_arn = batch.create_quota_share(
        quotaShareName=qs_name,
        jobQueue=setup["queue_name"],
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 5}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        tags={"sim2real": "true"},
    )["quotaShareArn"]
    ctx.on_cleanup(lambda: _safe_delete_quota_share(batch, qs_arn))

    desc = _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=qs_arn),
        lambda d: d["status"] == "VALID",
        timeout_s=180,
    )
    assert desc["state"] == "ENABLED", f"expected newly created quota share to be ENABLED, got {desc['state']!r}"

    # Break exactly one precondition: try to delete while still ENABLED/in-use.
    code, message = _error_code(lambda: batch.delete_quota_share(quotaShareArn=qs_arn))
    assert code == "ClientException", f"expected ClientException deleting an ENABLED quota share, got {code!r}"
    expected = "Quota Share must be DISABLED before deleting."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The forbidden effect did not happen: the quota share is still there, unchanged.
    still_there = batch.describe_quota_share(quotaShareArn=qs_arn)
    assert still_there["state"] == "ENABLED", f"expected state ENABLED after rejected delete, got {still_there['state']!r}"
    assert still_there["status"] in ("VALID", "UPDATING"), f"expected status VALID/UPDATING, got {still_there['status']!r}"
    assert still_there["quotaShareArn"] == qs_arn, f"expected quotaShareArn {qs_arn!r}, got {still_there['quotaShareArn']!r}"

    # Positive control: fixing the precondition (disable) allows the same delete to succeed.
    batch.update_quota_share(quotaShareArn=qs_arn, state="DISABLED")
    _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=qs_arn),
        lambda d: d["state"] == "DISABLED" and d["status"] == "VALID",
        timeout_s=120,
    )
    batch.delete_quota_share(quotaShareArn=qs_arn)

    deadline = time.monotonic() + 180
    last_code, last_message = None, None
    while time.monotonic() < deadline:
        try:
            batch.describe_quota_share(quotaShareArn=qs_arn)
        except ClientError as exc:
            last_code, last_message = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
            break
        time.sleep(3)
    assert last_code == "ClientException", "expected quota share to be gone after the disabled delete succeeded"
    expected_gone = f"{qs_arn} does not exist."
    assert last_message == expected_gone, f"expected message {expected_gone!r}, got {last_message!r}"

    # Gone is not just unreadable — a mutation against the dead id fails the same way.
    mutate_code, mutate_message = _error_code(lambda: batch.update_quota_share(quotaShareArn=qs_arn, state="ENABLED"))
    assert mutate_code == "ClientException", (
        f"expected ClientException updating a deleted quota share, got {mutate_code!r}"
    )
    assert mutate_message == expected_gone, f"expected message {expected_gone!r}, got {mutate_message!r}"


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused with a ClientError, but it succeeded")


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _safe_delete_quota_share(batch, arn):
    try:
        batch.update_quota_share(quotaShareArn=arn, state="DISABLED")
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ClientException"
            and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
        ):
            raise
    for _ in range(20):
        try:
            desc = batch.describe_quota_share(quotaShareArn=arn)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
            return
        if desc.get("status") == "VALID":
            break
        time.sleep(3)
    batch.delete_quota_share(quotaShareArn=arn)


def _create_quota_share_job_queue(ctx, teardown_deadline, *, with_scheduling_policy=True):
    batch = ctx.client("batch")
    policy_arn = None
    if with_scheduling_policy:
        policy_name = ctx.unique_name("sim2real-batch-qsp-")
        policy_arn = batch.create_scheduling_policy(
            name=policy_name,
            quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
            tags={"sim2real": "true"},
        )["arn"]

        def _cleanup_policy():
            _delete_when_released(lambda: batch.delete_scheduling_policy(arn=policy_arn), teardown_deadline)

        ctx.on_cleanup(_cleanup_policy)

    env_name = ctx.unique_name("sim2real-batch-senv-")
    env_arn = batch.create_service_environment(
        serviceEnvironmentName=env_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 10}],
        tags={"sim2real": "true"},
    )["serviceEnvironmentArn"]

    def _cleanup_env():
        try:
            batch.update_service_environment(serviceEnvironment=env_arn, state="DISABLED")
            for _ in range(40):
                d = batch.describe_service_environments(serviceEnvironments=[env_arn])
                if d["serviceEnvironments"][0]["status"] in ("VALID", "INVALID"):
                    break
                time.sleep(3)
            _delete_when_released(
                lambda: batch.delete_service_environment(serviceEnvironment=env_arn), teardown_deadline
            )
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise

    ctx.on_cleanup(_cleanup_env)
    _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[env_arn])["serviceEnvironments"][0],
        lambda e: e["status"] == "VALID",
        timeout_s=120,
    )

    queue_name = ctx.unique_name("sim2real-batch-qsq-")
    create_kwargs = dict(
        jobQueueName=queue_name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        serviceEnvironmentOrder=[{"serviceEnvironment": env_arn, "order": 1}],
        tags={"sim2real": "true"},
    )
    if policy_arn:
        create_kwargs["schedulingPolicyArn"] = policy_arn
    queue_arn = batch.create_job_queue(**create_kwargs)["jobQueueArn"]

    def _cleanup_queue():
        try:
            batch.update_job_queue(jobQueue=queue_arn, state="DISABLED")
            for _ in range(40):
                d = batch.describe_job_queues(jobQueues=[queue_arn])
                if d["jobQueues"][0]["status"] in ("VALID", "INVALID"):
                    break
                time.sleep(3)
            _delete_when_released(lambda: batch.delete_job_queue(jobQueue=queue_arn), teardown_deadline)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise

    ctx.on_cleanup(_cleanup_queue)
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[queue_arn])["jobQueues"][0],
        lambda q: q["status"] == "VALID",
        timeout_s=120,
    )
    return {"policy_arn": policy_arn, "env_arn": env_arn, "queue_name": queue_name, "queue_arn": queue_arn}


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
