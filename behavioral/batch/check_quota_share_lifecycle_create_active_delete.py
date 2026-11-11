"""quota-share-lifecycle-create-active-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "quota-share-lifecycle-create-active-delete"
GROUP = "state-machine"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateQuotaShare yields an ACTIVE (ENABLED/VALID) share visible via DescribeQuotaShare
    and ListQuotaShares; disabling then DeleteQuotaShare removes it from subsequent listings."""
    batch = ctx.client("batch")

    senv_name = _create_service_environment(ctx)
    sp_arn = _create_scheduling_policy(ctx)
    jq_name = _create_job_queue(ctx, senv_name, sp_arn)

    qs_name = ctx.unique_name("sim2real-batch-qs-")
    created = batch.create_quota_share(
        quotaShareName=qs_name,
        jobQueue=jq_name,
        capacityLimits=[{"capacityUnit": "ml.m6i.large", "maxCapacity": 5}],
        resourceSharingConfiguration={"strategy": "LEND_AND_BORROW", "borrowLimit": 100},
        preemptionConfiguration={"inSharePreemption": "ENABLED"},
        tags=_MANAGED_TAGS,
    )
    qs_arn = created["quotaShareArn"]
    ctx.on_cleanup(lambda: _delete_quota_share_best_effort(ctx, qs_arn))

    desc = _wait_for(
        lambda: batch.describe_quota_share(quotaShareArn=qs_arn),
        lambda d: d["status"] == "VALID",
    )
    assert desc["state"] == "ENABLED", f"expected state ENABLED, got {desc['state']!r}"
    assert desc["quotaShareName"] == qs_name, f"expected quotaShareName {qs_name!r}, got {desc['quotaShareName']!r}"
    assert desc["jobQueueArn"].endswith(jq_name), f"expected jobQueueArn to end with {jq_name!r}, got {desc['jobQueueArn']!r}"

    listed = batch.list_quota_shares(jobQueue=jq_name)["quotaShares"]
    names = [q["quotaShareName"] for q in listed]
    assert qs_name in names, f"expected {qs_name} in {names}"

    # Delete requires the share to be DISABLED first.
    batch.update_quota_share(quotaShareArn=qs_arn, state="DISABLED")
    _wait_for(
        lambda: batch.describe_quota_share(quotaShareArn=qs_arn),
        lambda d: d["status"] == "VALID" and d["state"] == "DISABLED",
    )
    batch.delete_quota_share(quotaShareArn=qs_arn)

    def _absent_from_list():
        shares = batch.list_quota_shares(jobQueue=jq_name)["quotaShares"]
        return qs_name not in [q["quotaShareName"] for q in shares]

    _wait_for_bool(_absent_from_list, timeout_s=90)

    # The delete is durable, not just absent from a list snapshot: an independent Describe
    # on the same ARN — an operation that demonstrably succeeded above — now fails with the
    # service's specific not-found code rather than returning stale VALID/ENABLED state.
    code, message = _client_error(lambda: batch.describe_quota_share(quotaShareArn=qs_arn), wait_s=90)
    assert code == "ClientException", f"expected ClientException describing a deleted quota share, got {code!r}"
    assert message == f"{qs_arn} does not exist.", f"expected {qs_arn + ' does not exist.'!r}, got {message!r}"


def _wait_for(probe, predicate, *, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _wait_for_bool(probe, *, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last:
            return
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s; last={last!r}")


def _client_error(fn, *, wait_s=0.0, interval_s=2.0):
    """Call fn() until it raises a ClientError; return (Error.Code, Error.Message). If the call
    still SUCCEEDS once wait_s has elapsed, raise: an emulator that accepts what AWS refuses
    must fail loudly, not read as a code mismatch."""
    deadline = time.monotonic() + wait_s
    while True:
        try:
            result = fn()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")
        time.sleep(interval_s)


def _create_service_environment(ctx, capacity_unit="ml.m6i.large", max_capacity=10):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-senv-")
    batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": capacity_unit, "maxCapacity": max_capacity}],
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_service_environment(ctx, name))
    _wait_for(
        lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0],
        lambda se: se["status"] == "VALID",
    )
    return name


def _delete_service_environment(ctx, name):
    batch = ctx.client("batch")
    try:
        batch.update_service_environment(serviceEnvironment=name, state="DISABLED")
        _wait_for(
            lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0],
            lambda se: se["status"] == "VALID" and se["state"] == "DISABLED",
            timeout_s=60,
        )
        batch.delete_service_environment(serviceEnvironment=name)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


def _create_scheduling_policy(ctx):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")
    created = batch.create_scheduling_policy(
        name=name,
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags=_MANAGED_TAGS,
    )
    arn = created["arn"]
    ctx.on_cleanup(lambda: _delete_scheduling_policy_best_effort(ctx, arn))
    return arn


def _delete_scheduling_policy_best_effort(ctx, arn):
    batch = ctx.client("batch")
    batch.delete_scheduling_policy(arn=arn)


def _create_job_queue(ctx, service_env_name, scheduling_policy_arn):
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
    ctx.on_cleanup(lambda: _delete_job_queue(ctx, name))
    _wait_for(
        lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"][0],
        lambda jq: jq["status"] == "VALID",
    )
    return name


def _delete_job_queue(ctx, name):
    batch = ctx.client("batch")
    try:
        batch.update_job_queue(jobQueue=name, state="DISABLED")
        _wait_for(
            lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"][0],
            lambda jq: jq["status"] == "VALID" and jq["state"] == "DISABLED",
            timeout_s=60,
        )
        batch.delete_job_queue(jobQueue=name)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
