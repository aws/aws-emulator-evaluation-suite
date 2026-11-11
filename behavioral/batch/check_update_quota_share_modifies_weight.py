"""update-quota-share-modifies-weight."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-quota-share-modifies-weight"
GROUP = "quota-share"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateQuotaShare changes the capacity limit / resource-sharing strategy and the
    change is visible on the next DescribeQuotaShare once the update settles to VALID."""
    batch = ctx.client("batch")
    setup = _create_quota_share_job_queue(ctx)

    qs_name = ctx.unique_name("sim2real-batch-qs-")
    qs_arn = batch.create_quota_share(
        quotaShareName=qs_name,
        jobQueue=setup["queue_name"],
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 5}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        tags=dict(_MANAGED_TAGS),
    )["quotaShareArn"]
    ctx.on_cleanup(lambda: _safe_delete_quota_share(batch, qs_arn))

    before = _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=qs_arn),
        lambda d: d["status"] == "VALID",
        timeout_s=180,
    )
    assert before["capacityLimits"] == [{"capacityUnit": "ml.m5.large", "maxCapacity": 5}], (
        f"expected initial capacityLimits [ml.m5.large:5], got {before['capacityLimits']!r}"
    )
    assert before["resourceSharingConfiguration"]["strategy"] == "RESERVE", (
        f"expected initial strategy RESERVE, got {before['resourceSharingConfiguration']!r}"
    )

    batch.update_quota_share(
        quotaShareArn=qs_arn,
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 20}],
        resourceSharingConfiguration={"strategy": "LEND_AND_BORROW", "borrowLimit": 50},
        preemptionConfiguration={"inSharePreemption": "ENABLED"},
    )

    after = _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=qs_arn),
        lambda d: d["status"] == "VALID" and d["capacityLimits"] == [{"capacityUnit": "ml.m5.large", "maxCapacity": 20}],
        timeout_s=180,
    )
    assert after["resourceSharingConfiguration"] == {"strategy": "LEND_AND_BORROW", "borrowLimit": 50}, (
        f"expected updated resourceSharingConfiguration LEND_AND_BORROW/50, got {after['resourceSharingConfiguration']!r}"
    )
    assert after["preemptionConfiguration"] == {"inSharePreemption": "ENABLED"}, (
        f"expected updated preemptionConfiguration ENABLED, got {after['preemptionConfiguration']!r}"
    )
    # Update must not have touched identity/association fields.
    assert after["quotaShareName"] == qs_name, (
        f"expected quotaShareName to survive update unchanged: {qs_name!r} vs {after['quotaShareName']!r}"
    )
    assert after["jobQueueArn"] == setup["queue_arn"], (
        f"expected jobQueueArn to survive update unchanged: {setup['queue_arn']!r} vs {after['jobQueueArn']!r}"
    )


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


def _create_quota_share_job_queue(ctx, *, with_scheduling_policy=True):
    batch = ctx.client("batch")
    policy_arn = None
    if with_scheduling_policy:
        policy_name = ctx.unique_name("sim2real-batch-qsp-")
        policy_arn = batch.create_scheduling_policy(
            name=policy_name,
            quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
            tags=dict(_MANAGED_TAGS),
        )["arn"]

        def _cleanup_policy():
            batch.delete_scheduling_policy(arn=policy_arn)

        ctx.on_cleanup(_cleanup_policy)

    env_name = ctx.unique_name("sim2real-batch-senv-")
    env_arn = batch.create_service_environment(
        serviceEnvironmentName=env_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 10}],
        tags=dict(_MANAGED_TAGS),
    )["serviceEnvironmentArn"]

    def _cleanup_env():
        try:
            batch.update_service_environment(serviceEnvironment=env_arn, state="DISABLED")
            for _ in range(40):
                d = batch.describe_service_environments(serviceEnvironments=[env_arn])
                if d["serviceEnvironments"][0]["status"] in ("VALID", "INVALID"):
                    break
                time.sleep(3)
            batch.delete_service_environment(serviceEnvironment=env_arn)
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
        tags=dict(_MANAGED_TAGS),
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
            batch.delete_job_queue(jobQueue=queue_arn)
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
