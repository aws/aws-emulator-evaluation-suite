"""create-quota-share-invalid-account-id-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-quota-share-invalid-account-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateQuotaShare where the jobQueue field is a malformed ARN carrying a
    non-12-digit account id segment is rejected as invalid input -- a distinct
    malformed-input boundary from an empty/missing capacityLimits field.
    """
    batch = ctx.client("batch")
    scheduling_policy_arn = _create_quota_scheduling_policy(ctx)
    service_env = _create_service_environment(ctx)
    job_queue = _create_service_job_queue(ctx, service_env["arn"], scheduling_policy_arn)

    malformed_arn = f"arn:aws:batch:{ctx.region}:12345:job-queue/nonexistent-queue"
    bad_name = ctx.unique_name("sim2real-batch-qs-badacct-")

    code, message, request_id = _error_code(
        lambda: batch.create_quota_share(
            quotaShareName=bad_name,
            jobQueue=malformed_arn,
            capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 5}],
            resourceSharingConfiguration={"strategy": "RESERVE"},
            preemptionConfiguration={"inSharePreemption": "ENABLED"},
            tags=_MANAGED_TAGS,
        )
    )
    # Real AWS Batch rejects a malformed jobQueue ARN with BadRequestException, a
    # distinct, earlier boundary than the ClientException a well-formed-but-nonexistent
    # jobQueue draws.
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    expected_message = (
        f"{malformed_arn}/quota-share/{bad_name} is not a valid AmazonResourceName (ARN)"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no quota share with that name was created anywhere reachable,
    # in particular not silently attached to our real (valid-account) job queue.
    listed = batch.list_quota_shares(jobQueue=job_queue["arn"])["quotaShares"]
    listed_names = [qs["quotaShareName"] for qs in listed]
    assert bad_name not in listed_names, (
        f"expected {bad_name!r} to be absent from {listed_names!r} after the rejected create"
    )

    # Positive control: the identical request with a well-formed, real job queue ARN
    # succeeds.
    good_name = ctx.unique_name("sim2real-batch-qs-goodacct-")
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
        f"expected {good_name!r} in {listed_after_names!r} after the well-formed create"
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


def _create_quota_scheduling_policy(ctx):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")
    resp = batch.create_scheduling_policy(
        name=name,
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags=_MANAGED_TAGS,
    )
    arn = resp["arn"]

    def _cleanup():
        batch.delete_scheduling_policy(arn=arn)

    ctx.on_cleanup(_cleanup)
    return arn


def _try_delete(fn):
    try:
        fn()
        return True
    except ClientError:
        return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
