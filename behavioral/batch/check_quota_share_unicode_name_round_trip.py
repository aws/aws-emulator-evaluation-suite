"""quota-share-unicode-name-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "quota-share-unicode-name-round-trip"
GROUP = "representation"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeQuotaShare returns byte-identical a 128-character name using every allowed
    quotaShareName character class, a 256-character tag value of every allowed tag character
    and spaces, and a maxCapacity of 2^31 - 1: no truncation, case-folding or normalization."""
    batch = ctx.client("batch")

    senv_name = _create_service_environment(ctx)
    sp_arn = _create_scheduling_policy(ctx)
    jq_name = _create_job_queue(ctx, senv_name, sp_arn)

    base = ctx.unique_name("sim2real-batch-QSrepr-")
    # Pad out to the 128-char max with a repeating mixed-case/digit/hyphen/underscore pattern to
    # exercise the full allowed character set at the length boundary.
    filler_pattern = "aZ9-_"
    qs_name = (base + (filler_pattern * 30))[:128]

    # Every special character CreateQuotaShare/Tags accepts (letters, numbers, spaces, and
    # + - = . _ : / @), repeated to the documented 256-character tag-value maximum.
    charset_unit = "AbC123 +-=.:/@_"
    tag_value = (charset_unit * 20)[:256]
    exact_capacity = 2147483647  # int32 boundary

    created = batch.create_quota_share(
        quotaShareName=qs_name,
        jobQueue=jq_name,
        capacityLimits=[{"capacityUnit": "ml.m6i.large", "maxCapacity": exact_capacity}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        tags={"sim2real-repr": tag_value},
    )
    qs_arn = created["quotaShareArn"]
    ctx.on_cleanup(lambda: _delete_quota_share_best_effort(ctx, qs_arn))

    desc = _wait_for(
        lambda: batch.describe_quota_share(quotaShareArn=qs_arn),
        lambda d: d["status"] == "VALID",
    )

    assert desc["quotaShareName"] == qs_name, (
        f"128-char mixed-case/digit/hyphen/underscore name must round-trip byte-identical, "
        f"got {desc['quotaShareName']!r}"
    )
    assert desc["capacityLimits"] == [{"capacityUnit": "ml.m6i.large", "maxCapacity": exact_capacity}], (
        f"int32-boundary capacity limit must round-trip exactly, got {desc['capacityLimits']!r}"
    )
    assert desc["tags"]["sim2real-repr"] == tag_value, (
        "256-char special-character tag value must round-trip byte-identical with no "
        f"truncation/normalization, got {desc['tags'].get('sim2real-repr')!r}"
    )
    assert len(desc["tags"]["sim2real-repr"]) == len(tag_value) == 256


def _wait_for(probe, predicate, *, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_service_environment(ctx, capacity_unit="ml.m6i.large", max_capacity=10):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-senv-")
    batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": capacity_unit, "maxCapacity": max_capacity}],
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
        _retry_delete(lambda: batch.delete_service_environment(serviceEnvironment=name))
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
    )
    arn = created["arn"]
    ctx.on_cleanup(lambda: _delete_scheduling_policy_best_effort(ctx, arn))
    return arn


def _delete_scheduling_policy_best_effort(ctx, arn):
    batch = ctx.client("batch")
    _retry_delete(lambda: batch.delete_scheduling_policy(arn=arn))


def _create_job_queue(ctx, service_env_name, scheduling_policy_arn):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-jq-")
    batch.create_job_queue(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": service_env_name}],
        schedulingPolicyArn=scheduling_policy_arn,
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
        _retry_delete(lambda: batch.delete_job_queue(jobQueue=name))
        _wait_jq_gone(batch, name)
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
        _retry_delete(lambda: batch.delete_quota_share(quotaShareArn=arn))
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ClientException"
            and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
        ):
            raise


def _retry_delete(fn, timeout_s=300.0):
    """Run a Batch delete; retry its ClientException refusals every 2 s to timeout_s while a
    dependent finishes deleting. A "does not exist" answer is done; every other error raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                return
            if err["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _wait_jq_gone(batch, name, timeout_s=300.0):
    """Poll every 2 s until DescribeJobQueues lists the queue absent or DELETED."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        queues = batch.describe_job_queues(jobQueues=[name])["jobQueues"]
        if not queues or queues[0]["status"] == "DELETED":
            return
        time.sleep(2)
    raise AssertionError(f"job queue {name} still present {timeout_s:.0f}s after DeleteJobQueue")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
