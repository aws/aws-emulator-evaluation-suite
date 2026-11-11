"""create-quota-share-nonexistent-job-queue-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-quota-share-nonexistent-job-queue-rejected"
GROUP = "state-machine"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateQuotaShare against a nonexistent jobQueue is rejected, creates nothing, and a valid queue still works."""
    batch = ctx.client("batch")
    queue_name = _setup_quota_management_queue(ctx, batch)

    bogus_queue_name = ctx.unique_name("sim2real-batch-no-such-queue-")
    bogus_share_name = ctx.unique_name("sim2real-batch-qs-bogus-")

    code, message, request_id = _error_code(
        lambda: batch.create_quota_share(
            quotaShareName=bogus_share_name,
            jobQueue=bogus_queue_name,
            capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 2}],
            resourceSharingConfiguration={"strategy": "RESERVE"},
            preemptionConfiguration={"inSharePreemption": "ENABLED"},
        )
    )
    assert code == "ClientException", f"expected ClientException, got {code!r}"
    # Batch embeds the call's own request id in this message.
    expected_message = (
        f"Error executing request, Exception : {bogus_queue_name} does not exist., "
        f"RequestId: {request_id}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the rejected share must not exist under the (still nonexistent) bogus
    # queue itself, nor leak onto the real queue
    bogus_listed = batch.list_quota_shares(jobQueue=bogus_queue_name).get("quotaShares", [])
    assert bogus_listed == [], (
        f"expected no quota shares listed for the nonexistent queue {bogus_queue_name!r}, "
        f"got {bogus_listed!r}"
    )
    real_names = _list_quota_share_names(batch, queue_name)
    assert bogus_share_name not in real_names, (
        f"rejected share {bogus_share_name!r} must not appear under the real queue "
        f"{queue_name!r}, saw {real_names!r}"
    )

    # positive control: the exact same call succeeds against the real, VALID job queue
    real_share_name = ctx.unique_name("sim2real-batch-qs-real-")
    created = batch.create_quota_share(
        quotaShareName=real_share_name,
        jobQueue=queue_name,
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 2}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "ENABLED"},
        tags={"sim2real": "true"},
    )
    quota_share_arn = created["quotaShareArn"]

    def _cleanup_share():
        try:
            batch.update_quota_share(quotaShareArn=quota_share_arn, state="DISABLED")
            _poll_until(
                lambda: batch.describe_quota_share(quotaShareArn=quota_share_arn),
                lambda d: d["state"] == "DISABLED" and d["status"] == "VALID",
                timeout_s=120,
            )
            batch.delete_quota_share(quotaShareArn=quota_share_arn)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
            ):
                raise

        # DeleteQuotaShare is asynchronous, and DeleteJobQueue is refused while a share remains.
        def _gone():
            try:
                batch.describe_quota_share(quotaShareArn=quota_share_arn)
                return False
            except ClientError as exc:
                err = exc.response["Error"]
                if not (
                    err["Code"] == "ClientException"
                    and "does not exist" in err.get("Message", "")
                ):
                    raise
                return True

        _poll_until(_gone, lambda g: g, timeout_s=120)

    ctx.on_cleanup(_cleanup_share)

    _poll_until(
        lambda: _list_quota_share_names(batch, queue_name),
        lambda names: real_share_name in names,
        timeout_s=60,
    )


def _error_code(fn):
    """Call fn(); return its botocore Error (code, message, request id). An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response["ResponseMetadata"].get("RequestId"),
        )
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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
