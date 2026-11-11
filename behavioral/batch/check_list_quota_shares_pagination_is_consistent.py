"""list-quota-shares-pagination-is-consistent."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-quota-shares-pagination-is-consistent"
GROUP = "ordering"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListQuotaShares with a small page size returns every quota share exactly once."""
    batch = ctx.client("batch")
    queue = _create_quota_managed_job_queue(ctx)

    created_names = set()
    for i in range(5):
        name = ctx.unique_name(f"sim2real-batch-qs-{i}-")
        resp = batch.create_quota_share(
            quotaShareName=name,
            jobQueue=queue["jobQueueArn"],
            capacityLimits=[{"maxCapacity": 1, "capacityUnit": "ml.m5.large"}],
            resourceSharingConfiguration={"strategy": "RESERVE"},
            preemptionConfiguration={"inSharePreemption": "DISABLED"},
            tags={"env": "sim2real-behav"},
        )
        arn = resp["quotaShareArn"]
        created_names.add(name)
        ctx.on_cleanup(lambda a=arn: _best_effort_delete(ctx, a))
        _wait_quota_share_status(ctx, arn, {"VALID"})

    seen_names: list[str] = []
    next_token = None
    pages = 0
    while True:
        kwargs = {"jobQueue": queue["jobQueueArn"], "maxResults": 2}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = batch.list_quota_shares(**kwargs)
        pages += 1
        page_items = resp.get("quotaShares", [])
        assert len(page_items) <= 2, f"maxResults=2 must return at most 2 items, got {len(page_items)}"
        for item in page_items:
            seen_names.append(item["quotaShareName"])
        next_token = resp.get("nextToken")
        if not next_token:
            break
        assert pages < 50  # sanity bound against a runaway pagination loop

    seen_for_test = [n for n in seen_names if n in created_names]
    assert pages >= 3  # 5 items at page size 2 must span at least 3 pages
    assert sorted(seen_for_test) == sorted(created_names)  # no omissions
    assert len(seen_for_test) == len(set(seen_for_test))  # no duplicates


# ===== helpers =====


def _retry_client_exception(call, timeout_s):
    """Retry a delete Batch refuses with ClientException while a dependency releases, every 2 s,
    then raise; a resource reported as not existing is already gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except ClientError as exc:
            message = exc.response["Error"].get("Message", "")
            if exc.response["Error"]["Code"] == "ClientException" and (
                "does not exist" in message or "not found" in message
            ):
                return None
            if exc.response["Error"]["Code"] != "ClientException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _best_effort_delete(ctx, arn):
    batch = ctx.client("batch")
    try:
        batch.update_quota_share(quotaShareArn=arn, state="DISABLED")
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ClientException"
            and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
        ):
            raise
    _retry_client_exception(lambda: batch.delete_quota_share(quotaShareArn=arn), timeout_s=60)


def _wait_quota_share_status(ctx, arn, target_statuses, timeout_s=120):
    batch = ctx.client("batch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = batch.describe_quota_share(quotaShareArn=arn)
        last = resp
        if resp["status"] in target_statuses:
            return resp
        if resp["status"] == "INVALID":
            raise AssertionError(f"quota share became INVALID: {resp}")
        time.sleep(3)
    raise AssertionError(f"quota share never reached {target_statuses}, last={last}")


def _wait_service_environment_valid(ctx, arn, timeout_s=180):
    batch = ctx.client("batch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = batch.describe_service_environments(serviceEnvironments=[arn])
        envs = resp.get("serviceEnvironments", [])
        if envs:
            status = envs[0]["status"]
            if status == "VALID":
                return envs[0]
            if status == "INVALID":
                raise AssertionError(f"service environment became INVALID: {envs[0]}")
        time.sleep(3)
    raise AssertionError("service environment did not reach VALID in time")


def _wait_job_queue_valid(ctx, arn, timeout_s=180):
    batch = ctx.client("batch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = batch.describe_job_queues(jobQueues=[arn])
        queues = resp.get("jobQueues", [])
        if queues:
            status = queues[0]["status"]
            if status == "VALID":
                return queues[0]
            if status == "INVALID":
                raise AssertionError(f"job queue became INVALID: {queues[0]}")
        time.sleep(3)
    raise AssertionError("job queue did not reach VALID in time")


def _safe_delete_scheduling_policy(ctx, arn):
    batch = ctx.client("batch")
    _retry_client_exception(lambda: batch.delete_scheduling_policy(arn=arn), timeout_s=60)


def _create_quota_managed_job_queue(ctx):
    batch = ctx.client("batch")
    sp_name = ctx.unique_name("sim2real-batch-sp-")
    sp = batch.create_scheduling_policy(
        name=sp_name,
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags={"env": "sim2real-behav"},
    )
    sp_arn = sp["arn"]
    ctx.on_cleanup(lambda: _safe_delete_scheduling_policy(ctx, sp_arn))

    se_name = ctx.unique_name("sim2real-batch-se-")
    se = batch.create_service_environment(
        serviceEnvironmentName=se_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"maxCapacity": 2, "capacityUnit": "ml.m5.large"}],
        tags={"env": "sim2real-behav"},
    )
    se_arn = se["serviceEnvironmentArn"]

    def _cleanup_se():
        try:
            batch.update_service_environment(serviceEnvironment=se_arn, state="DISABLED")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
        _retry_client_exception(lambda: batch.delete_service_environment(serviceEnvironment=se_arn), timeout_s=90)

    ctx.on_cleanup(_cleanup_se)
    _wait_service_environment_valid(ctx, se_arn)

    jq_name = ctx.unique_name("sim2real-batch-jq-")
    jq = batch.create_job_queue(
        jobQueueName=jq_name,
        priority=1,
        jobQueueType="SAGEMAKER_TRAINING",
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": se_arn}],
        schedulingPolicyArn=sp_arn,
        tags={"env": "sim2real-behav"},
    )
    jq_arn = jq["jobQueueArn"]

    def _cleanup_jq():
        try:
            batch.update_job_queue(jobQueue=jq_arn, state="DISABLED")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
        _retry_client_exception(lambda: batch.delete_job_queue(jobQueue=jq_arn), timeout_s=90)

    ctx.on_cleanup(_cleanup_jq)
    _wait_job_queue_valid(ctx, jq_arn)
    return {
        "jobQueueArn": jq_arn,
        "jobQueueName": jq_name,
        "serviceEnvironmentArn": se_arn,
        "schedulingPolicyArn": sp_arn,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
