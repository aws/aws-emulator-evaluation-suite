"""quota-share-lifecycle-create-update-delete-404."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "quota-share-lifecycle-create-update-delete-404"
GROUP = "state-machine"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateQuotaShare -> UpdateQuotaShare persists on DescribeQuotaShare -> DeleteQuotaShare -> 404."""
    batch = ctx.client("batch")
    queue_name = _setup_quota_management_queue(ctx, batch)

    quota_share_name = ctx.unique_name("sim2real-batch-qs-")
    created = batch.create_quota_share(
        quotaShareName=quota_share_name,
        jobQueue=queue_name,
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 2}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "ENABLED"},
    )
    quota_share_arn = created["quotaShareArn"]
    ctx.on_cleanup(lambda: _delete_quota_share_best_effort(batch, quota_share_arn))

    described = _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=quota_share_arn),
        lambda d: d["status"] == "VALID",
        timeout_s=120,
    )
    assert described["capacityLimits"][0]["maxCapacity"] == 2, (
        f"expected capacityLimits[0].maxCapacity == 2, got {described['capacityLimits']}"
    )
    assert described["resourceSharingConfiguration"]["strategy"] == "RESERVE", (
        f"expected strategy RESERVE, got {described['resourceSharingConfiguration']}"
    )

    batch.update_quota_share(
        quotaShareArn=quota_share_arn,
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 4}],
        state="DISABLED",
    )
    described = _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=quota_share_arn),
        lambda d: d["status"] == "VALID",
        timeout_s=120,
    )
    assert described["capacityLimits"][0]["maxCapacity"] == 4, "updated capacityLimits did not persist"
    assert described["state"] == "DISABLED", "updated state did not persist"

    batch.delete_quota_share(quotaShareArn=quota_share_arn)

    code, message = _client_error(
        lambda: batch.describe_quota_share(quotaShareArn=quota_share_arn), wait_s=120, interval_s=3.0
    )
    assert code == "ClientException", f"expected ClientException describing a deleted quota share, got {code!r}"
    expected = f"{quota_share_arn} does not exist."
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # A mutation on the now-deleted id must also fail, not just the read.
    update_code, update_message = _client_error(
        lambda: batch.update_quota_share(quotaShareArn=quota_share_arn, state="ENABLED")
    )
    assert update_code == "ClientException", (
        f"expected ClientException updating a deleted quota share, got {update_code!r}"
    )
    assert update_message == expected, f"expected {expected!r}, got {update_message!r}"


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


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _delete_quota_share_best_effort(batch, quota_share_arn) -> None:
    try:
        batch.update_quota_share(quotaShareArn=quota_share_arn, state="DISABLED")
        _poll_until(
            lambda: batch.describe_quota_share(quotaShareArn=quota_share_arn),
            lambda d: d["status"] == "VALID" and d["state"] == "DISABLED",
            timeout_s=60,
        )
        batch.delete_quota_share(quotaShareArn=quota_share_arn)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ClientException"
            and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
        ):
            raise


def _best_effort_delete_scheduling_policy(batch, policy_arn) -> None:
    batch.delete_scheduling_policy(arn=policy_arn)


def _disable_and_delete_job_queue(batch, queue_name) -> None:
    try:
        batch.update_job_queue(jobQueue=queue_name, state="DISABLED")
        _poll_until(
            lambda: batch.describe_job_queues(jobQueues=[queue_name])["jobQueues"][0],
            lambda q: q["status"] in ("VALID", "INVALID"),
            timeout_s=120,
        )
        batch.delete_job_queue(jobQueue=queue_name)
        _poll_until(
            lambda: batch.describe_job_queues(jobQueues=[queue_name])["jobQueues"],
            lambda qs: len(qs) == 0,
            timeout_s=180,
        )
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


def _disable_and_delete_service_environment(batch, env_name) -> None:
    try:
        batch.update_service_environment(serviceEnvironment=env_name, state="DISABLED")
        _poll_until(
            lambda: batch.describe_service_environments(serviceEnvironments=[env_name])["serviceEnvironments"][0],
            lambda e: e["status"] in ("VALID", "INVALID"),
            timeout_s=120,
        )
        batch.delete_service_environment(serviceEnvironment=env_name)
        _poll_until(
            lambda: batch.describe_service_environments(serviceEnvironments=[env_name])["serviceEnvironments"],
            lambda es: len(es) == 0,
            timeout_s=180,
        )
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


def _setup_quota_management_queue(ctx, batch) -> str:
    """Create a quota-management-enabled SAGEMAKER_TRAINING job queue and return its name."""
    policy_name = ctx.unique_name("sim2real-batch-qsp-")
    policy = batch.create_scheduling_policy(
        name=policy_name, quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"}
    )
    policy_arn = policy["arn"]
    ctx.on_cleanup(lambda: _best_effort_delete_scheduling_policy(batch, policy_arn))

    env_name = ctx.unique_name("sim2real-batch-senv-")
    batch.create_service_environment(
        serviceEnvironmentName=env_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 10}],
    )
    ctx.on_cleanup(lambda: _disable_and_delete_service_environment(batch, env_name))
    _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[env_name])["serviceEnvironments"][0],
        lambda e: e["status"] == "VALID",
        timeout_s=120,
    )

    queue_name = ctx.unique_name("sim2real-batch-qmq-")
    batch.create_job_queue(
        jobQueueName=queue_name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        schedulingPolicyArn=policy_arn,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": env_name}],
    )
    ctx.on_cleanup(lambda: _disable_and_delete_job_queue(batch, queue_name))
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[queue_name])["jobQueues"][0],
        lambda q: q["status"] == "VALID",
        timeout_s=120,
    )
    return queue_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
