"""quota-share-unicode-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "quota-share-unicode-name-rejected"
GROUP = "representation"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateQuotaShare with a non-ASCII quotaShareName fails with ClientException and the exact
    message and creates no share, while a valid ASCII name on the same job queue succeeds: the
    name pattern allows only letters, digits, hyphens and underscores."""
    batch = ctx.client("batch")

    senv_name = _create_service_environment(ctx)
    sp_arn = _create_scheduling_policy(ctx)
    jq_name = _create_job_queue(ctx, senv_name, sp_arn)

    bad_name = ctx.unique_name("sim2real-batch-qs-") + "\u00e9\u4e2d\u6587"
    code, message, request_id = _client_error(
        lambda: batch.create_quota_share(
            quotaShareName=bad_name,
            jobQueue=jq_name,
            capacityLimits=[{"capacityUnit": "ml.m6i.large", "maxCapacity": 5}],
            resourceSharingConfiguration={"strategy": "RESERVE"},
            preemptionConfiguration={"inSharePreemption": "DISABLED"},
        )
    )
    assert code == "ClientException", f"expected ClientException for a unicode name, got {code!r}"
    expected = (
        "Error executing request, Exception : quotaShareName should match a valid pattern., "
        f"RequestId: {request_id}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    listed = batch.list_quota_shares(jobQueue=jq_name)["quotaShares"]
    names = [q["quotaShareName"] for q in listed]
    assert bad_name not in names, f"rejected quota share must not have been created, found in {names}"

    # Positive control: a valid ASCII name on the same job queue must succeed.
    good_name = ctx.unique_name("sim2real-batch-qs-good-")
    created = batch.create_quota_share(
        quotaShareName=good_name,
        jobQueue=jq_name,
        capacityLimits=[{"capacityUnit": "ml.m6i.large", "maxCapacity": 5}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        tags={"sim2real": "true"},
    )
    good_arn = created["quotaShareArn"]
    ctx.on_cleanup(lambda: _delete_quota_share_best_effort(ctx, good_arn))
    desc = _wait_for(
        lambda: batch.describe_quota_share(quotaShareArn=good_arn),
        lambda d: d["status"] == "VALID",
    )
    assert desc["quotaShareName"] == good_name, (
        f"ASCII-named positive control must round-trip its name, expected {good_name!r}, "
        f"got {desc['quotaShareName']!r}"
    )


def _client_error(fn):
    """Call fn(); return (Error.Code, Error.Message, RequestId) of its ClientError. An unexpected
    success raises, so accepting a name AWS refuses fails as itself and not as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response.get("ResponseMetadata", {}).get("RequestId"),
        )
    raise AssertionError(
        f"expected ClientException for a unicode quotaShareName, but the call SUCCEEDED and "
        f"returned {result!r}"
    )


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
        tags={"sim2real": "true"},
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
        tags={"sim2real": "true"},
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
        tags={"sim2real": "true"},
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
