"""quota-share-lifecycle-state-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "quota-share-lifecycle-state-transitions"
GROUP = "state-machine"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateQuotaShare->VALID, UpdateQuotaShare mutates in place, DeleteQuotaShare removes it."""
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
        _delete_retrying(lambda: batch.delete_quota_share(quotaShareArn=qs_arn), 60)

    ctx.on_cleanup(_cleanup_qs)

    # CREATING -> VALID
    created = _wait_quota_share_status(ctx, qs_arn, {"VALID"})
    assert created["capacityLimits"][0]["maxCapacity"] == 1, (
        f"expected initial maxCapacity 1, got {created['capacityLimits'][0]['maxCapacity']!r}"
    )

    # UpdateQuotaShare mutates the resource in place
    batch.update_quota_share(
        quotaShareArn=qs_arn,
        capacityLimits=[{"maxCapacity": 3, "capacityUnit": "ml.m5.large"}],
    )
    updated = _wait_quota_share_status(ctx, qs_arn, {"VALID"})
    assert updated["capacityLimits"][0]["maxCapacity"] == 3, (
        f"expected updated maxCapacity 3, got {updated['capacityLimits'][0]['maxCapacity']!r}"
    )
    assert updated["quotaShareArn"] == qs_arn, (
        f"expected quotaShareArn to persist as {qs_arn!r}, got {updated['quotaShareArn']!r}"
    )

    # Must be DISABLED before it can be deleted
    batch.update_quota_share(quotaShareArn=qs_arn, state="DISABLED")
    disabled = _wait_quota_share_status(ctx, qs_arn, {"VALID"})
    assert disabled["state"] == "DISABLED", f"expected state DISABLED, got {disabled['state']!r}"

    # DeleteQuotaShare removes it; a subsequent Describe reports not-found
    batch.delete_quota_share(quotaShareArn=qs_arn)
    _wait_quota_share_deleted(ctx, qs_arn)

    # Gone is not just unreadable — a mutation against the dead id fails the same way.
    try:
        batch.update_quota_share(quotaShareArn=qs_arn, state="ENABLED")
        raise AssertionError("expected update of a deleted quota share to fail")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "ClientException", f"expected ClientException updating a deleted quota share, got {code!r}"
        assert message == f"{qs_arn} does not exist.", f"expected {qs_arn + ' does not exist.'!r}, got {message!r}"


# ===== helpers =====


def _delete_retrying(delete, budget_s):
    """Run a Batch delete; a resource that does not exist is done. Batch refuses a delete with
    ClientException while a dependent resource is still releasing, so that is retried every 2 s
    until budget_s, then raised."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            delete()
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                return
            if err["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


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
    _delete_retrying(lambda: batch.delete_scheduling_policy(arn=arn), 60)


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
        _delete_retrying(lambda: batch.delete_service_environment(serviceEnvironment=se_arn), 90)

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
        _delete_retrying(lambda: batch.delete_job_queue(jobQueue=jq_arn), 90)

    ctx.on_cleanup(_cleanup_jq)
    _wait_job_queue_valid(ctx, jq_arn)
    return {
        "jobQueueArn": jq_arn,
        "jobQueueName": jq_name,
        "serviceEnvironmentArn": se_arn,
        "schedulingPolicyArn": sp_arn,
    }


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


def _wait_quota_share_deleted(ctx, arn, timeout_s=120):
    batch = ctx.client("batch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            batch.describe_quota_share(quotaShareArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ClientException":
                return
            raise
        time.sleep(3)
    raise AssertionError("quota share was not reported not-found after delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
