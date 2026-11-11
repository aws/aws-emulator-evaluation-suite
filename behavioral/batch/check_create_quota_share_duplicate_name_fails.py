"""create-quota-share-duplicate-name-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-quota-share-duplicate-name-fails"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateQuotaShare with a quotaShareName that collides with an existing active
    quota share on the same job queue is rejected with ClientException rather than
    silently overwriting the original quota share's configuration."""
    batch = ctx.client("batch")
    stack = _setup_quota_management_job_queue(ctx)
    jq_arn = stack["job_queue_arn"]

    name = ctx.unique_name("sim2real-batch-qs-")
    original_arn = _create_quota_share(
        ctx, jq_arn, name=name, max_capacity=1, strategy="RESERVE", in_share_preemption="DISABLED"
    )
    _wait_quota_share_status(batch, original_arn, {"VALID", "INVALID"})

    code, message = _error(
        lambda: batch.create_quota_share(
            quotaShareName=name,
            jobQueue=jq_arn,
            capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 99}],
            resourceSharingConfiguration={"strategy": "LEND"},
            preemptionConfiguration={"inSharePreemption": "ENABLED"},
        )
    )
    assert code == "ClientException", f"expected ClientException for duplicate name, got {code}"
    expected_message = f"QuotaShare with name {name} already exists for job queue {jq_arn}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: exactly one quota share carries this name, and its original
    # capacity/strategy were not overwritten by the rejected duplicate attempt.
    shares = batch.list_quota_shares(jobQueue=jq_arn)["quotaShares"]
    matching = [s for s in shares if s["quotaShareName"] == name]
    assert len(matching) == 1, f"expected exactly one quota share named {name!r}, found {len(matching)}"
    detail = batch.describe_quota_share(quotaShareArn=original_arn)
    assert detail["capacityLimits"] == [{"capacityUnit": "ml.m5.large", "maxCapacity": 1}], detail
    assert detail["resourceSharingConfiguration"]["strategy"] == "RESERVE", detail

    # positive control: a differently-named quota share on the same job queue still creates fine.
    other_name = ctx.unique_name("sim2real-batch-qs-")
    other_arn = _create_quota_share(ctx, jq_arn, name=other_name, max_capacity=1)
    assert other_arn != original_arn, f"expected a distinct quota share arn, got {other_arn!r} == {original_arn!r}"

    other_detail = batch.describe_quota_share(quotaShareArn=other_arn)
    assert other_detail["quotaShareName"] == other_name, other_detail


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but call succeeded and returned {result!r}")


def _retry_client_error(fn, timeout_s=300.0, interval_s=10.0):
    """Retry a teardown delete while Batch still reports a dependent relationship."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError:
            if time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


def _quota_share_gone(batch, arn):
    try:
        return batch.describe_quota_share(quotaShareArn=arn).get("status") == "DELETED"
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
        return True


def _wait_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_quota_scheduling_policy(ctx):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-qmsp-")
    arn = batch.create_scheduling_policy(
        name=name,
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags={"sim2real": "true"},
    )["arn"]
    ctx.on_cleanup(lambda: _retry_client_error(lambda: batch.delete_scheduling_policy(arn=arn)))
    return arn


def _create_sagemaker_service_environment(ctx):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-qmse-")
    arn = batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 1}],
        tags={"sim2real": "true"},
    )["serviceEnvironmentArn"]

    def _cleanup():
        try:
            batch.update_service_environment(serviceEnvironment=arn, state="DISABLED")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
        _wait_until(
            lambda: batch.describe_service_environments(serviceEnvironments=[arn])["serviceEnvironments"],
            lambda envs: not envs or envs[0]["status"] in ("VALID", "INVALID"),
        )
        _retry_client_error(lambda: batch.delete_service_environment(serviceEnvironment=arn))
        _wait_until(
            lambda: batch.describe_service_environments(serviceEnvironments=[arn])["serviceEnvironments"],
            lambda envs: not envs or envs[0]["status"] == "DELETED",
            timeout_s=300.0,
        )

    ctx.on_cleanup(_cleanup)
    _wait_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[arn])["serviceEnvironments"],
        lambda envs: envs and envs[0]["status"] in ("VALID", "INVALID"),
    )
    return name, arn


def _create_sagemaker_job_queue(ctx, scheduling_policy_arn, service_environment_name):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-qmjq-")
    arn = batch.create_job_queue(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        state="ENABLED",
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": service_environment_name}],
        schedulingPolicyArn=scheduling_policy_arn,
        tags={"sim2real": "true"},
    )["jobQueueArn"]

    def _cleanup():
        try:
            batch.update_job_queue(jobQueue=arn, state="DISABLED")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
        _wait_until(
            lambda: batch.describe_job_queues(jobQueues=[arn])["jobQueues"],
            lambda qs: not qs or qs[0]["status"] in ("VALID", "INVALID"),
        )
        _retry_client_error(lambda: batch.delete_job_queue(jobQueue=arn))
        _wait_until(
            lambda: batch.describe_job_queues(jobQueues=[arn])["jobQueues"],
            lambda qs: not qs or qs[0]["status"] == "DELETED",
            timeout_s=300.0,
        )

    ctx.on_cleanup(_cleanup)
    _wait_until(
        lambda: batch.describe_job_queues(jobQueues=[arn])["jobQueues"],
        lambda qs: qs and qs[0]["status"] in ("VALID", "INVALID"),
    )
    return name, arn


def _setup_quota_management_job_queue(ctx):
    sp_arn = _create_quota_scheduling_policy(ctx)
    se_name, se_arn = _create_sagemaker_service_environment(ctx)
    jq_name, jq_arn = _create_sagemaker_job_queue(ctx, sp_arn, se_name)
    return {
        "scheduling_policy_arn": sp_arn,
        "service_environment_arn": se_arn,
        "job_queue_name": jq_name,
        "job_queue_arn": jq_arn,
    }


def _create_quota_share(ctx, job_queue, name=None, max_capacity=1, strategy="RESERVE", in_share_preemption="DISABLED"):
    batch = ctx.client("batch")
    name = name or ctx.unique_name("sim2real-batch-qs-")
    arn = batch.create_quota_share(
        quotaShareName=name,
        jobQueue=job_queue,
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": max_capacity}],
        resourceSharingConfiguration={"strategy": strategy},
        preemptionConfiguration={"inSharePreemption": in_share_preemption},
        tags={"sim2real": "true"},
    )["quotaShareArn"]

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
        _wait_until(
            lambda: batch.describe_quota_share(quotaShareArn=arn),
            lambda q: q.get("state") == "DISABLED" and q.get("status") in ("VALID", "INVALID"),
        )
        _retry_client_error(lambda: batch.delete_quota_share(quotaShareArn=arn))
        _wait_until(lambda: _quota_share_gone(batch, arn), bool, timeout_s=300.0)

    ctx.on_cleanup(_cleanup)
    return arn


def _wait_quota_share_status(batch, arn, target_statuses, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = batch.describe_quota_share(quotaShareArn=arn)
        if last.get("status") in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"quota share {arn} did not reach {target_statuses}; last status={last.get('status') if last else None}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
