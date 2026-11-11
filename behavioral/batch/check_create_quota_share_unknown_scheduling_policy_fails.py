"""create-quota-share-unknown-scheduling-policy-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-quota-share-unknown-scheduling-policy-fails"
GROUP = "error-semantics"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateQuotaShare on a nonexistent job queue fails with ClientException and creates no share,
    while the same call on a real quota-management queue succeeds."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    batch = ctx.client("batch")
    bogus_queue = ctx.unique_name("sim2real-batch-noqueue-")
    quota_share_name = ctx.unique_name("sim2real-batch-qs-")

    try:
        result = batch.create_quota_share(
            quotaShareName=quota_share_name,
            jobQueue=bogus_queue,
            capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 1}],
            resourceSharingConfiguration={"strategy": "RESERVE"},
            preemptionConfiguration={"inSharePreemption": "DISABLED"},
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message")
        request_id = err.response["ResponseMetadata"].get("RequestId")
    else:
        raise AssertionError(
            f"expected a rejection, but the call SUCCEEDED and returned {result!r}"
        )

    assert code == "ClientException", f"expected ClientException, got {code!r}"
    # Batch embeds the call's own request id in this message.
    expected_message = (
        f"Error executing request, Exception : {bogus_queue} does not exist., "
        f"RequestId: {request_id}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The quota share must not have been created: ListQuotaShares against the (still
    # nonexistent) queue does not error (real AWS Batch just filters by the given
    # jobQueue without requiring it to exist) but must come back empty, i.e. it never
    # shows our rejected create attempt.
    listed = batch.list_quota_shares(jobQueue=bogus_queue).get("quotaShares", [])
    assert listed == [], (
        f"expected no quota shares listed for the missing job queue, got {listed!r}"
    )

    # Positive control: without this, the rejection above is indistinguishable from
    # "CreateQuotaShare always fails in this account". The identical call, unchanged
    # but for jobQueue, must succeed against a real quota-management-enabled queue.
    senv_name = _create_service_environment(ctx, teardown_deadline)
    sp_arn = _create_scheduling_policy(ctx, teardown_deadline)
    jq_name = _create_job_queue(ctx, senv_name, sp_arn, teardown_deadline)

    real_share_name = ctx.unique_name("sim2real-batch-qs-real-")
    real_share_arn = batch.create_quota_share(
        quotaShareName=real_share_name,
        jobQueue=jq_name,
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 1}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        tags=_MANAGED_TAGS,
    )["quotaShareArn"]
    ctx.on_cleanup(lambda: _delete_quota_share_best_effort(ctx, real_share_arn))

    # Terminal read independent of the mutating CreateQuotaShare call: the accepted
    # share becomes visible via ListQuotaShares at the real (valid) queue.
    _wait_for(
        lambda: _list_quota_share_names(batch, jq_name),
        lambda names: real_share_name in names,
        timeout_s=60,
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


def _list_quota_share_names(batch, queue_name):
    names = set()
    token = None
    while True:
        kwargs = {"jobQueue": queue_name}
        if token:
            kwargs["nextToken"] = token
        resp = batch.list_quota_shares(**kwargs)
        for qs in resp.get("quotaShares", []):
            names.add(qs["quotaShareName"])
        token = resp.get("nextToken")
        if not token:
            break
    return names


def _create_service_environment(ctx, teardown_deadline, capacity_unit="ml.m5.large", max_capacity=10):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-senv-")
    batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": capacity_unit, "maxCapacity": max_capacity}],
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_service_environment(ctx, name, teardown_deadline))
    _wait_for(
        lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0],
        lambda se: se["status"] == "VALID",
    )
    return name


def _delete_service_environment(ctx, name, teardown_deadline):
    batch = ctx.client("batch")
    try:
        batch.update_service_environment(serviceEnvironment=name, state="DISABLED")
        _wait_for(
            lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0],
            lambda se: se["status"] == "VALID" and se["state"] == "DISABLED",
            timeout_s=60,
        )
        _delete_when_released(lambda: batch.delete_service_environment(serviceEnvironment=name), teardown_deadline)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


def _create_scheduling_policy(ctx, teardown_deadline):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")
    created = batch.create_scheduling_policy(
        name=name,
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags=_MANAGED_TAGS,
    )
    arn = created["arn"]
    ctx.on_cleanup(lambda: _delete_scheduling_policy_best_effort(ctx, arn, teardown_deadline))
    return arn


def _delete_scheduling_policy_best_effort(ctx, arn, teardown_deadline):
    batch = ctx.client("batch")
    _delete_when_released(lambda: batch.delete_scheduling_policy(arn=arn), teardown_deadline)


def _create_job_queue(ctx, service_env_name, scheduling_policy_arn, teardown_deadline):
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
    ctx.on_cleanup(lambda: _delete_job_queue(ctx, name, teardown_deadline))
    _wait_for(
        lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"][0],
        lambda jq: jq["status"] == "VALID",
    )
    return name


def _delete_job_queue(ctx, name, teardown_deadline):
    batch = ctx.client("batch")
    try:
        batch.update_job_queue(jobQueue=name, state="DISABLED")
        _wait_for(
            lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"][0],
            lambda jq: jq["status"] == "VALID" and jq["state"] == "DISABLED",
            timeout_s=60,
        )
        _delete_when_released(lambda: batch.delete_job_queue(jobQueue=name), teardown_deadline)
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


# The batch suite's cleanup budget (900 s), one deadline shared by every teardown of a run.
_TEARDOWN_RETRY_S = 900.0


def _delete_when_released(call, teardown_deadline) -> None:
    """Run a Batch delete; while Batch refuses it with "Cannot delete, found existing ..."
    (a dependent still deleting), retry every 2 s to the shared deadline; raise everything else."""
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 120.0)
    while True:
        try:
            call()
            return
        except ClientError as exc:
            err = exc.response["Error"]
            in_use = err["Code"] == "ClientException" and err.get("Message", "").startswith(
                "Cannot delete, found existing"
            )
            if not in_use or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
