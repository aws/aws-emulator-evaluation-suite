"""create-quota-share-duplicate-name-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-quota-share-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateQuotaShare reusing a live quota share's name on the same job queue is a ClientException.

    The refusal is tied to the name being in use: once the holder is deleted the identical call succeeds.
    """
    batch = ctx.client("batch")
    se_name = _create_service_environment(ctx)
    sp_arn = _create_scheduling_policy(ctx)
    jq_arn, _jq_name = _create_job_queue(ctx, se_name, scheduling_policy_arn=sp_arn)
    qs_arn, qs_name = _create_quota_share(ctx, jq_arn, max_capacity=1)

    code, message, request_id = _error_code(
        lambda: batch.create_quota_share(
            quotaShareName=qs_name,
            jobQueue=jq_arn,
            capacityLimits=[{"maxCapacity": 5, "capacityUnit": "ml.m6i.large"}],
            resourceSharingConfiguration={"strategy": "LEND"},
            preemptionConfiguration={"inSharePreemption": "DISABLED"},
        )
    )
    assert code == "ClientException", f"expected ClientException, got {code}"
    expected_message = (
        f"QuotaShare with name {qs_name} already exists for job queue {jq_arn}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    shares = batch.list_quota_shares(jobQueue=jq_arn)["quotaShares"]
    matching = [s for s in shares if s["quotaShareName"] == qs_name]
    assert len(matching) == 1, f"expected exactly one quota share named {qs_name!r}, found {len(matching)}"
    described = batch.describe_quota_share(quotaShareArn=qs_arn)
    assert described["quotaShareArn"] == qs_arn, "the original quota share must be unaffected"
    assert described["capacityLimits"] == [{"maxCapacity": 1, "capacityUnit": "ml.m6i.large"}], (
        f"rejected duplicate must not overwrite capacityLimits, got {described['capacityLimits']!r}"
    )
    assert described["resourceSharingConfiguration"]["strategy"] == "RESERVE", (
        f"rejected duplicate must not overwrite strategy, got {described['resourceSharingConfiguration']!r}"
    )

    # restore: the rejection is tied to the name being in use right now, not a permanent
    # reservation of it. Delete the quota share holding the name, confirm via an independent
    # read that it is gone, then the identical create call -- same name -- succeeds.
    _delete_quota_share(ctx, qs_arn)
    recreated = batch.create_quota_share(
        quotaShareName=qs_name,
        jobQueue=jq_arn,
        capacityLimits=[{"maxCapacity": 1, "capacityUnit": "ml.m6i.large"}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "ENABLED"},
        tags=dict(_MANAGED_TAGS),
    )
    recreated_arn = recreated["quotaShareArn"]
    # the ARN is name-derived (arn:.../quota-share/<name>), so it is identical to the
    # deleted holder's. The object is proven live and
    # freshly-configured (not a resurrected stale one) by its state and its config.
    assert recreated_arn == qs_arn, (
        f"expected the name-derived ARN to be unchanged, got {recreated_arn!r} for {qs_arn!r}"
    )
    ctx.on_cleanup(lambda: _delete_quota_share(ctx, recreated_arn))
    live = _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=recreated_arn),
        lambda qs: qs["status"] == "VALID",
        timeout_s=90,
    )
    assert live["state"] == "ENABLED", f"expected the recreated share to be ENABLED, got {live['state']!r}"
    assert live["capacityLimits"] == [{"maxCapacity": 1, "capacityUnit": "ml.m6i.large"}], (
        f"expected the recreated share's own capacityLimits, got {live['capacityLimits']!r}"
    )

    # positive control: a differently named quota share on the same queue succeeds
    other_arn, other_name = _create_quota_share(ctx, jq_arn, max_capacity=1)
    described_other = batch.describe_quota_share(quotaShareArn=other_arn)
    assert described_other["quotaShareName"] == other_name, (
        f"expected quota share name {other_name!r}, got {described_other['quotaShareName']!r}"
    )


from botocore.exceptions import ClientError

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch"}


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
    """Call fn(); return its botocore Error (code, message, request id).

    An unexpected SUCCESS raises: accepting input AWS refuses is reported as such, not as a code mismatch.
    """
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
    batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"maxCapacity": 2, "capacityUnit": "ml.m6i.large"}],
        tags=dict(_MANAGED_TAGS),
    )

    def _cleanup():
        try:
            batch.update_service_environment(serviceEnvironment=name, state="DISABLED")
            _poll_until(
                lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0],
                lambda se: se["state"] == "DISABLED",
                timeout_s=90,
            )
            batch.delete_service_environment(serviceEnvironment=name)
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


def _create_scheduling_policy(ctx, with_quota_share_policy=True):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")
    kwargs = {"name": name, "tags": dict(_MANAGED_TAGS)}
    if with_quota_share_policy:
        kwargs["quotaSharePolicy"] = {"idleResourceAssignmentStrategy": "FIFO"}
    resp = batch.create_scheduling_policy(**kwargs)
    arn = resp["arn"]

    def _cleanup():
        batch.delete_scheduling_policy(arn=arn)

    ctx.on_cleanup(_cleanup)
    return arn


def _create_job_queue(ctx, service_environment_name, scheduling_policy_arn=None, priority=1):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-jq-")
    kwargs = dict(
        jobQueueName=name,
        priority=priority,
        jobQueueType="SAGEMAKER_TRAINING",
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": service_environment_name}],
        tags=dict(_MANAGED_TAGS),
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
            # The queue refuses its delete while a quota-share removal or the disable is still
            # being applied to it: retry exactly that refusal every 2 s, then raise.
            deadline = time.monotonic() + 120
            while True:
                try:
                    batch.delete_job_queue(jobQueue=arn)
                    break
                except ClientError as exc:
                    if (
                        "resource is being modified" not in exc.response["Error"].get("Message", "")
                        or time.monotonic() >= deadline
                    ):
                        raise
                time.sleep(2)
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


def _delete_quota_share(ctx, arn):
    batch = ctx.client("batch")
    batch.update_quota_share(quotaShareArn=arn, state="DISABLED")
    _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=arn),
        lambda qs: qs["state"] == "DISABLED" and qs["status"] == "VALID",
        timeout_s=90,
    )
    batch.delete_quota_share(quotaShareArn=arn)

    def _probe_gone():
        try:
            batch.describe_quota_share(quotaShareArn=arn)
            return None
        except ClientError as e:
            if e.response["Error"]["Code"] == "ClientException":
                return "ClientException"
            raise

    _poll_until(_probe_gone, lambda code: code == "ClientException", timeout_s=90)


def _create_quota_share(ctx, job_queue_arn, quota_share_name=None, max_capacity=1, capacity_unit="ml.m6i.large"):
    batch = ctx.client("batch")
    name = quota_share_name or ctx.unique_name("sim2real-batch-qs-")
    resp = batch.create_quota_share(
        quotaShareName=name,
        jobQueue=job_queue_arn,
        capacityLimits=[{"maxCapacity": max_capacity, "capacityUnit": capacity_unit}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "ENABLED"},
        tags=dict(_MANAGED_TAGS),
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
