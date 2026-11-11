"""list-quota-shares-reflects-create-and-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-quota-shares-reflects-create-and-delete"
GROUP = "state-machine"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListQuotaShares includes a newly created quota share and omits it after deletion."""
    batch = ctx.client("batch")
    queue_name = _setup_quota_management_queue(ctx, batch)

    quota_share_name = ctx.unique_name("sim2real-batch-qs-")

    before_names = _list_quota_share_names(batch, queue_name)
    assert quota_share_name not in before_names

    created = batch.create_quota_share(
        quotaShareName=quota_share_name,
        jobQueue=queue_name,
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 2}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "ENABLED"},
        tags={"sim2real": "true"},
    )
    quota_share_arn = created["quotaShareArn"]

    _poll_until(
        lambda: _list_quota_share_names(batch, queue_name),
        lambda names: quota_share_name in names,
        timeout_s=60,
    )

    # disable then delete, so removal from the list-shares view is a legitimate lifecycle transition
    batch.update_quota_share(quotaShareArn=quota_share_arn, state="DISABLED")
    _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=quota_share_arn),
        lambda d: d["status"] == "VALID",
        timeout_s=120,
    )
    batch.delete_quota_share(quotaShareArn=quota_share_arn)

    _poll_until(
        lambda: _list_quota_share_names(batch, queue_name),
        lambda names: quota_share_name not in names,
        timeout_s=120,
    )

    # The delete is also unusable, not just absent from the list view: a mutation
    # against the dead arn must fail, never silently resurrect or no-op.
    mutate_code, mutate_message = _refusal_within(
        lambda: batch.update_quota_share(quotaShareArn=quota_share_arn, state="ENABLED"),
        timeout_s=60,
    )
    assert mutate_code == "ClientException", (
        f"expected ClientException updating a deleted quota share, got {mutate_code!r}"
    )
    expected_message = f"{quota_share_arn} does not exist."
    assert mutate_message == expected_message, f"expected message {expected_message!r}, got {mutate_message!r}"


def _refusal_within(fn, timeout_s=60.0, interval_s=3.0):
    """Retry fn() until it raises a ClientError and return its (Error.Code, Error.Message). A call
    that still succeeds at the deadline raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")
        if time.monotonic() > deadline:
            raise AssertionError(f"expected a rejection within {timeout_s}s, but the call kept succeeding: {result!r}")
        time.sleep(interval_s)


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


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _best_effort_delete_scheduling_policy(batch, policy_arn) -> None:
    try:
        batch.delete_scheduling_policy(arn=policy_arn)
    except ClientError:
        pass


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
        name=policy_name,
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags={"sim2real": "true"},
    )
    policy_arn = policy["arn"]
    ctx.on_cleanup(lambda: batch.delete_scheduling_policy(arn=policy_arn))

    env_name = ctx.unique_name("sim2real-batch-senv-")
    batch.create_service_environment(
        serviceEnvironmentName=env_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 10}],
        tags={"sim2real": "true"},
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
        tags={"sim2real": "true"},
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
