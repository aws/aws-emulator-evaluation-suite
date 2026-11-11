"""list-quota-shares-reflects-created-shares."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-quota-shares-reflects-created-shares"
GROUP = "quota-share"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListQuotaShares(jobQueue=...) returns exactly every quota share created under
    that job queue's quota-share scheduling policy, and nothing else."""
    batch = ctx.client("batch")
    setup = _create_quota_share_job_queue(ctx)

    expected_names = set()
    expected_arns = set()
    for i in range(3):
        name = ctx.unique_name(f"sim2real-batch-qs{i}-")
        created = batch.create_quota_share(
            quotaShareName=name,
            jobQueue=setup["queue_name"],
            capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 1 + i}],
            resourceSharingConfiguration={"strategy": "RESERVE"},
            preemptionConfiguration={"inSharePreemption": "DISABLED"},
            tags=_MANAGED_TAGS,
        )
        arn = created["quotaShareArn"]
        ctx.on_cleanup(lambda a=arn: _safe_delete_quota_share(batch, a))
        expected_names.add(name)
        expected_arns.add(arn)

    def _list_quota_shares():
        resp = batch.list_quota_shares(jobQueue=setup["queue_name"])
        return resp["quotaShares"]

    def _ours_reached_valid(quota_shares):
        ours = {qs["quotaShareName"]: qs for qs in quota_shares if qs["quotaShareName"] in expected_names}
        invalid = {name: qs["status"] for name, qs in ours.items() if qs["status"] == "INVALID"}
        if invalid:
            raise AssertionError(f"quota share(s) went INVALID instead of VALID: {invalid}")
        return len(ours) == len(expected_names) and all(qs["status"] == "VALID" for qs in ours.values())

    seen_qs = _poll_until(_list_quota_shares, _ours_reached_valid, timeout_s=120)

    seen_names = {qs["quotaShareName"] for qs in seen_qs}
    assert seen_names == expected_names, f"expected exactly {expected_names}, got {seen_names}"

    seen_arns = {qs["quotaShareArn"] for qs in seen_qs}
    assert seen_arns == expected_arns, f"expected exactly {expected_arns}, got {seen_arns}"
    for qs in seen_qs:
        assert qs["state"] == "ENABLED", f"expected ENABLED for {qs['quotaShareName']}, got {qs['state']}"
        assert qs["status"] == "VALID", f"expected VALID for {qs['quotaShareName']}, got {qs['status']}"


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
            tags=_MANAGED_TAGS,
        )["arn"]

        def _cleanup_policy():
            batch.delete_scheduling_policy(arn=policy_arn)

        ctx.on_cleanup(_cleanup_policy)

    env_name = ctx.unique_name("sim2real-batch-senv-")
    env_arn = batch.create_service_environment(
        serviceEnvironmentName=env_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 10}],
        tags=_MANAGED_TAGS,
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
        tags=_MANAGED_TAGS,
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
