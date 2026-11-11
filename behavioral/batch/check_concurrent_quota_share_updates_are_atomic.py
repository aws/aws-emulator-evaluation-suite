"""concurrent-quota-share-updates-are-atomic."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-quota-share-updates-are-atomic"
GROUP = "concurrency"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateQuotaShare calls resolve to one consistent value, no lost/torn write."""
    batch = ctx.client("batch")
    queue = _create_quota_managed_job_queue(ctx)

    create_resp = batch.create_quota_share(
        quotaShareName=ctx.unique_name("sim2real-batch-qs-"),
        jobQueue=queue["jobQueueArn"],
        capacityLimits=[{"maxCapacity": 1, "capacityUnit": "ml.m5.large"}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        tags={"sim2real": "true"},
    )
    qs_arn = create_resp["quotaShareArn"]

    def _cleanup_qs():
        try:
            batch.update_quota_share(quotaShareArn=qs_arn, state="DISABLED")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
            ):
                raise
        _retry_refused(lambda: batch.delete_quota_share(quotaShareArn=qs_arn))

    ctx.on_cleanup(_cleanup_qs)
    _wait_quota_share_status(ctx, qs_arn, {"VALID"})

    candidate_values = [11, 23]

    def _update(max_capacity):
        batch.update_quota_share(
            quotaShareArn=qs_arn,
            capacityLimits=[{"maxCapacity": max_capacity, "capacityUnit": "ml.m5.large"}],
        )
        return max_capacity

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_update, value) for value in candidate_values]
        results = [f.result() for f in futures]

    assert set(results) == set(candidate_values), (
        f"expected both racers to succeed with distinct values {candidate_values}, "
        f"got {results}"
    )

    final = _wait_quota_share_status(ctx, qs_arn, {"VALID"})
    final_capacity = final["capacityLimits"][0]["maxCapacity"]
    # The stored value must be EXACTLY one of the two racer values -- not a corrupted
    # or interleaved combination of the two concurrent writes.
    assert final_capacity in candidate_values, (
        f"final maxCapacity {final_capacity} is not one of the raced values "
        f"{candidate_values} -- torn or corrupted write"
    )



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


def _retry_refused(call, *, timeout_s=60):
    """Run a Batch teardown call, where "does not exist" means already gone.

    Batch answers ClientException while a dependency drains: retry that every 2 s, then raise.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                return None
            if err["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _safe_delete_scheduling_policy(ctx, arn):
    batch = ctx.client("batch")
    _retry_refused(lambda: batch.delete_scheduling_policy(arn=arn))


def _create_quota_managed_job_queue(ctx):
    batch = ctx.client("batch")
    sp_name = ctx.unique_name("sim2real-batch-sp-")
    sp = batch.create_scheduling_policy(
        name=sp_name,
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags={"sim2real": "true"},
    )
    sp_arn = sp["arn"]
    ctx.on_cleanup(lambda: _safe_delete_scheduling_policy(ctx, sp_arn))

    se_name = ctx.unique_name("sim2real-batch-se-")
    se = batch.create_service_environment(
        serviceEnvironmentName=se_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"maxCapacity": 2, "capacityUnit": "ml.m5.large"}],
        tags={"sim2real": "true"},
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
        _retry_refused(lambda: batch.delete_service_environment(serviceEnvironment=se_arn), timeout_s=90)

    ctx.on_cleanup(_cleanup_se)
    _wait_service_environment_valid(ctx, se_arn)

    jq_name = ctx.unique_name("sim2real-batch-jq-")
    jq = batch.create_job_queue(
        jobQueueName=jq_name,
        priority=1,
        jobQueueType="SAGEMAKER_TRAINING",
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": se_arn}],
        schedulingPolicyArn=sp_arn,
        tags={"sim2real": "true"},
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
        _retry_refused(lambda: batch.delete_job_queue(jobQueue=jq_arn), timeout_s=90)

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
