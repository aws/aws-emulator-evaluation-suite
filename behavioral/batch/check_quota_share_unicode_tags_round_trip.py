"""quota-share-unicode-tags-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "quota-share-unicode-tags-round-trip"
GROUP = "representation"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode tag values on a quota share round-trip byte-identical via TagResource/List/Describe."""
    batch = ctx.client("batch")
    sp_arn = _create_scheduling_policy(ctx)
    se = _create_service_environment(ctx)
    jq = _create_job_queue(ctx, se["name"], sp_arn)

    share_name = ctx.unique_name("sim2real-batch-qs-uni-").replace("-", "_")
    created = batch.create_quota_share(
        quotaShareName=share_name,
        jobQueue=jq["name"],
        capacityLimits=[{"maxCapacity": 2, "capacityUnit": "ml.m6i.large"}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
    )
    share_arn = created["quotaShareArn"]
    ctx.on_cleanup(lambda: _teardown_quota_share(ctx, share_arn))
    _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=share_arn),
        lambda d: d["status"] == "VALID",
        timeout_s=90,
    )

    # AWS tag values only permit letters, numbers, spaces, and a small set of
    # special characters (_ . : / = + - @); emoji and combining diacritical
    # marks are rejected with BadRequestException, so this uses only unicode
    # *letters* (from multiple scripts) plus the always-allowed separators.
    unicode_tags = {
        "sim2real-team": "\u65e5\u672c\u8a9e\u30c1\u30fc\u30e0",  # Japanese
        "sim2real-owner": "\u0645\u0627\u0644\u0643-\u0627\u0644\u0645\u0648\u0627\u0631\u062f",  # Arabic
        "sim2real-cyrillic": "\u043a\u043e\u043c\u0430\u043d\u0434\u0430-batch",  # Cyrillic
        "sim2real-accents": "cafe-r\u00e9sum\u00e9-\u00fcber",  # precomposed accented letters only
    }
    batch.tag_resource(resourceArn=share_arn, tags=unicode_tags)

    listed = batch.list_tags_for_resource(resourceArn=share_arn)["tags"]
    for key, value in unicode_tags.items():
        assert key in listed, f"missing tag key {key!r}"
        assert listed[key] == value, f"tag {key!r} mangled: {listed[key]!r} != {value!r}"

    described = batch.describe_quota_share(quotaShareArn=share_arn)
    described_tags = described.get("tags", {})
    for key, value in unicode_tags.items():
        assert described_tags.get(key) == value, (
            f"DescribeQuotaShare tag {key!r} mangled: {described_tags.get(key)!r} != {value!r}"
        )
    assert described["quotaShareName"] == share_name, (
        f"quotaShareName mismatch: {described['quotaShareName']!r} != {share_name!r}"
    )


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _create_scheduling_policy(ctx):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")
    arn = batch.create_scheduling_policy(
        name=name, quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"}
    )["arn"]
    ctx.on_cleanup(lambda: batch.delete_scheduling_policy(arn=arn))
    return arn


def _create_service_environment(ctx, capacity_unit="ml.m6i.large", max_capacity=2):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-se-")
    batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"maxCapacity": max_capacity, "capacityUnit": capacity_unit}],
    )
    ctx.on_cleanup(lambda: _teardown_service_environment(ctx, name))
    _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0],
        lambda se: se["status"] == "VALID",
        timeout_s=90,
    )
    return {"name": name}


def _teardown_service_environment(ctx, name):
    batch = ctx.client("batch")
    try:
        batch.update_service_environment(serviceEnvironment=name, state="DISABLED")
        _poll_until(
            lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0],
            lambda se: se["state"] == "DISABLED" and se["status"] == "VALID",
            timeout_s=90,
        )
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    batch.delete_service_environment(serviceEnvironment=name)


def _create_job_queue(ctx, service_environment_name, scheduling_policy_arn, priority=1):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-jq-")
    batch.create_job_queue(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=priority,
        schedulingPolicyArn=scheduling_policy_arn,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": service_environment_name}],
    )
    ctx.on_cleanup(lambda: _teardown_job_queue(ctx, name))
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"][0],
        lambda jq: jq["status"] == "VALID",
        timeout_s=90,
    )
    return {"name": name}


def _teardown_job_queue(ctx, name):
    batch = ctx.client("batch")
    try:
        batch.update_job_queue(jobQueue=name, state="DISABLED")
        _poll_until(
            lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"][0],
            lambda jq: jq["state"] == "DISABLED" and jq["status"] == "VALID",
            timeout_s=90,
        )
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    batch.delete_job_queue(jobQueue=name)


def _teardown_quota_share(ctx, quota_share_arn):
    batch = ctx.client("batch")
    try:
        batch.update_quota_share(quotaShareArn=quota_share_arn, state="DISABLED")
        _poll_until(
            lambda: batch.describe_quota_share(quotaShareArn=quota_share_arn),
            lambda d: d["state"] == "DISABLED" and d["status"] == "VALID",
            timeout_s=90,
        )
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ClientException"
            and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
        ):
            raise
    batch.delete_quota_share(quotaShareArn=quota_share_arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
