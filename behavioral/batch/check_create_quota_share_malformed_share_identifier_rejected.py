"""create-quota-share-malformed-share-identifier-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-quota-share-malformed-share-identifier-rejected"
GROUP = "overly-permissive"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateQuotaShare with a quotaShareName containing characters outside the
    documented [A-Za-z0-9_-] charset is rejected as malformed input."""
    batch = ctx.client("batch")
    se_name = _create_service_environment(ctx)
    sp_arn = _create_scheduling_policy(ctx)
    jq_arn, _jq_name = _create_job_queue(ctx, se_name, scheduling_policy_arn=sp_arn)
    # AWS Batch docs: quotaShareName "can contain uppercase and lowercase letters,
    # numbers, hyphens (-), and underscores (_)" -- append a space and '!' to break that.
    malformed_name = ctx.unique_name("sim2real-batch-qs-") + " !"

    code, message, request_id = _error_code(
        lambda: batch.create_quota_share(
            quotaShareName=malformed_name,
            jobQueue=jq_arn,
            capacityLimits=[{"maxCapacity": 1, "capacityUnit": "ml.m6i.large"}],
            resourceSharingConfiguration={"strategy": "RESERVE"},
            preemptionConfiguration={"inSharePreemption": "ENABLED"},
        )
    )
    assert code == "ClientException", f"expected ClientException, got {code}"
    # Batch embeds the call's own request id in this message.
    expected_message = (
        "Error executing request, Exception : quotaShareName should match a valid pattern., "
        f"RequestId: {request_id}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    shares = batch.list_quota_shares(jobQueue=jq_arn)["quotaShares"]
    assert not any(s["quotaShareName"] == malformed_name for s in shares), (
        "the rejected quota share with a malformed name must not have been created"
    )

    # positive control: a name using only the documented charset succeeds
    valid_arn, valid_name = _create_quota_share(ctx, jq_arn, max_capacity=1)
    described = batch.describe_quota_share(quotaShareArn=valid_arn)
    assert described["quotaShareName"] == valid_name


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
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
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
        tags=_MANAGED_TAGS,
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
    kwargs = {"name": name, "tags": _MANAGED_TAGS}
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
        tags=_MANAGED_TAGS,
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
            batch.delete_job_queue(jobQueue=arn)
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
        tags=_MANAGED_TAGS,
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
