"""create-quota-share-invalid-share-identifier-fails."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-quota-share-invalid-share-identifier-fails"
GROUP = "error-semantics"
SERVICES = ["batch"]

RESOURCE_TAGS = {"sim2real-check": CHECK}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateQuotaShare with a quotaShareName over the 128-character limit is rejected with
    ClientException and creates no share, while an in-bounds name on the same job queue succeeds."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    batch = ctx.client("batch")
    se_name = _create_service_environment(ctx, teardown_deadline)
    sp_arn = _create_scheduling_policy(ctx, teardown_deadline)
    jq_arn, _jq_name = _create_job_queue(ctx, se_name, teardown_deadline, scheduling_policy_arn=sp_arn)

    # Positive control: a normal, in-bounds name succeeds -- proves the account and
    # queue are otherwise healthy before we blame the identifier itself.
    valid_arn, valid_name = _create_quota_share(ctx, jq_arn, max_capacity=1)
    described = batch.describe_quota_share(quotaShareArn=valid_arn)
    assert described["quotaShareName"] == valid_name, (
        f"expected the positive-control quota share to report its own name, got {described!r}"
    )
    assert len(valid_name) <= 128, f"positive control name {valid_name!r} unexpectedly exceeds the 128-char bound"

    # Break exactly one precondition: keep the documented charset (letters, digits,
    # hyphens, underscores) but push the name past the documented 128-character limit.
    oversized_name = ctx.unique_name("sim2real-batch-qs-") + ("a" * 140)
    assert len(oversized_name) > 128, f"test name {oversized_name!r} is not actually oversized"

    code, message, request_id = _error_code(
        lambda: batch.create_quota_share(
            quotaShareName=oversized_name,
            jobQueue=jq_arn,
            capacityLimits=[{"maxCapacity": 1, "capacityUnit": "ml.m6i.large"}],
            resourceSharingConfiguration={"strategy": "RESERVE"},
            preemptionConfiguration={"inSharePreemption": "ENABLED"},
        )
    )
    assert code == "ClientException", (
        f"expected ClientException for a quotaShareName over the documented 128-char limit, got {code!r}"
    )
    # Batch embeds the call's own request id in this message.
    expected_message = (
        "Error executing request, Exception : quotaShareName should match a valid pattern., "
        f"RequestId: {request_id}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent, via an independent read: only the positive control's quota share
    # exists on this queue -- the oversized-name attempt never landed.
    shares = batch.list_quota_shares(jobQueue=jq_arn)["quotaShares"]
    assert not any(s["quotaShareName"] == oversized_name for s in shares), (
        f"the rejected oversized-name quota share must not appear in ListQuotaShares, got {shares!r}"
    )
    matching_valid = [s for s in shares if s["quotaShareName"] == valid_name]
    assert len(matching_valid) == 1, f"expected exactly 1 quota share named {valid_name!r}, found {matching_valid!r}"


from botocore.exceptions import ClientError


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


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


def _create_service_environment(ctx, teardown_deadline):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-se-")
    batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"maxCapacity": 2, "capacityUnit": "ml.m6i.large"}],
        tags=RESOURCE_TAGS,
    )

    def _cleanup():
        try:
            batch.update_service_environment(serviceEnvironment=name, state="DISABLED")
            _poll_until(
                lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0],
                lambda se: se["state"] == "DISABLED",
                timeout_s=90,
            )
            _delete_when_released(lambda: batch.delete_service_environment(serviceEnvironment=name), teardown_deadline)
            _poll_until(
                lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"],
                lambda ses: len(ses) == 0,
                timeout_s=150,
            )
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0],
        lambda se: se["status"] == "VALID",
        timeout_s=90,
    )
    return name


def _create_scheduling_policy(ctx, teardown_deadline, with_quota_share_policy=True):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")
    kwargs = {"name": name, "tags": RESOURCE_TAGS}
    if with_quota_share_policy:
        kwargs["quotaSharePolicy"] = {"idleResourceAssignmentStrategy": "FIFO"}
    resp = batch.create_scheduling_policy(**kwargs)
    arn = resp["arn"]

    def _cleanup():
        _delete_when_released(lambda: batch.delete_scheduling_policy(arn=arn), teardown_deadline)

    ctx.on_cleanup(_cleanup)
    return arn


def _create_job_queue(ctx, service_environment_name, teardown_deadline, scheduling_policy_arn=None, priority=1):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-jq-")
    kwargs = dict(
        jobQueueName=name,
        priority=priority,
        jobQueueType="SAGEMAKER_TRAINING",
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": service_environment_name}],
        tags=RESOURCE_TAGS,
    )
    if scheduling_policy_arn:
        kwargs["schedulingPolicyArn"] = scheduling_policy_arn
    resp = batch.create_job_queue(**kwargs)
    arn = resp["jobQueueArn"]

    def _cleanup():
        try:
            batch.update_job_queue(jobQueue=arn, state="DISABLED")
            _poll_until(
                lambda: batch.describe_job_queues(jobQueues=[arn])["jobQueues"][0],
                lambda jq: jq["state"] == "DISABLED",
                timeout_s=90,
            )
            _delete_when_released(lambda: batch.delete_job_queue(jobQueue=arn), teardown_deadline)
            _poll_until(
                lambda: batch.describe_job_queues(jobQueues=[arn])["jobQueues"],
                lambda jqs: len(jqs) == 0,
                timeout_s=180,
            )
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[arn])["jobQueues"][0],
        lambda jq: jq["status"] == "VALID",
        timeout_s=90,
    )
    return arn, name


def _create_quota_share(ctx, job_queue_arn, quota_share_name=None, max_capacity=1, capacity_unit="ml.m6i.large"):
    batch = ctx.client("batch")
    name = quota_share_name or ctx.unique_name("sim2real-batch-qs-")
    resp = batch.create_quota_share(
        quotaShareName=name,
        jobQueue=job_queue_arn,
        capacityLimits=[{"maxCapacity": max_capacity, "capacityUnit": capacity_unit}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "ENABLED"},
        tags=RESOURCE_TAGS,
    )
    arn = resp["quotaShareArn"]

    def _cleanup():
        try:
            batch.update_quota_share(quotaShareArn=arn, state="DISABLED")
            _poll_until(
                lambda: batch.describe_quota_share(quotaShareArn=arn),
                lambda qs: qs["state"] == "DISABLED",
                timeout_s=90,
            )
            batch.delete_quota_share(quotaShareArn=arn)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
            ):
                raise

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=arn),
        lambda qs: qs["status"] == "VALID",
        timeout_s=90,
    )
    return arn, name


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
