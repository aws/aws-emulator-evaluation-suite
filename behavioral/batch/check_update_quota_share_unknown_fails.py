"""update-quota-share-unknown-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-quota-share-unknown-fails"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateQuotaShare on a quota-share ARN under a job queue that never existed fails with
    ClientException "<arn> does not exist." and DescribeQuotaShare then fails the same way, while
    the check's own quota share takes and keeps an update to strategy LEND."""
    batch = ctx.client("batch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    stack = _setup_quota_management_job_queue(ctx)
    jq_arn = stack["job_queue_arn"]

    real_arn = _create_quota_share(ctx, jq_arn)
    _wait_quota_share_status(batch, real_arn, {"VALID", "INVALID"})

    # positive control: updating the quota share this check created succeeds and persists.
    batch.update_quota_share(quotaShareArn=real_arn, resourceSharingConfiguration={"strategy": "LEND"})
    updated = _wait_until(
        lambda: batch.describe_quota_share(quotaShareArn=real_arn),
        lambda d: d["resourceSharingConfiguration"]["strategy"] == "LEND",
    )
    assert updated["resourceSharingConfiguration"]["strategy"] == "LEND", (
        f"positive control failed: expected strategy LEND, got {updated['resourceSharingConfiguration']!r}"
    )

    # break exactly one thing: a well-formed quota-share ARN under a job queue that was
    # never created at all.
    fake_jq_name = ctx.unique_name("sim2real-batch-nonexistent-jq-")
    fake_qs_name = ctx.unique_name("sim2real-batch-nonexistent-qs-")
    fake_arn = f"arn:aws:batch:{ctx.region}:{account_id}:job-queue/{fake_jq_name}/quota-share/{fake_qs_name}"

    code, message = _client_error(lambda: batch.update_quota_share(quotaShareArn=fake_arn, state="ENABLED"))
    assert code == "ClientException", f"expected ClientException for unknown quota share, got {code!r}"
    expected_message = f"{fake_arn} does not exist."
    assert message == expected_message, (
        f"expected message {expected_message!r} for unknown quota share, got {message!r}"
    )

    # effect absent: the failed update did not conjure a describable resource under the
    # fake ARN, and the real quota share's earlier successful update is untouched.
    describe_code, describe_message = _client_error(lambda: batch.describe_quota_share(quotaShareArn=fake_arn))
    assert describe_code == "ClientException", (
        f"unknown quota share became describable after a failed update: {describe_code!r}"
    )
    expected_describe_message = f"{fake_arn} does not exist."
    assert describe_message == expected_describe_message, (
        f"expected message {expected_describe_message!r} describing the unknown quota share, "
        f"got {describe_message!r}"
    )
    after = batch.describe_quota_share(quotaShareArn=real_arn)
    assert after["resourceSharingConfiguration"]["strategy"] == "LEND", (
        f"real quota share's config changed after an unrelated failed update: {after['resourceSharingConfiguration']!r}"
    )


def _client_error(fn):
    """Call fn() expecting an AWS refusal; return its (Error.Code, Error.Message).

    Raises AssertionError when the call succeeds, so a missing refusal never reaches an assert
    as a falsy value.
    """
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused with a ClientError, but it succeeded")


def _wait_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_quota_scheduling_policy(ctx):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-qmsp-")
    arn = batch.create_scheduling_policy(
        name=name,
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags={"env": "sim2real-behav"},
    )["arn"]
    ctx.on_cleanup(lambda: batch.delete_scheduling_policy(arn=arn))
    return arn


def _create_sagemaker_service_environment(ctx):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-qmse-")
    arn = batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 1}],
        tags={"env": "sim2real-behav"},
    )["serviceEnvironmentArn"]

    def _cleanup():
        try:
            batch.update_service_environment(serviceEnvironment=arn, state="DISABLED")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
        _wait_until(
            lambda: batch.describe_service_environments(serviceEnvironments=[arn])["serviceEnvironments"],
            lambda envs: not envs or envs[0]["status"] in ("VALID", "INVALID"),
        )
        batch.delete_service_environment(serviceEnvironment=arn)

    ctx.on_cleanup(_cleanup)
    _wait_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[arn])["serviceEnvironments"],
        lambda envs: envs and envs[0]["status"] in ("VALID", "INVALID"),
    )
    return name, arn


def _create_sagemaker_job_queue(ctx, scheduling_policy_arn, service_environment_name):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-qmjq-")
    arn = batch.create_job_queue(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        state="ENABLED",
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": service_environment_name}],
        schedulingPolicyArn=scheduling_policy_arn,
        tags={"env": "sim2real-behav"},
    )["jobQueueArn"]

    def _cleanup():
        try:
            batch.update_job_queue(jobQueue=arn, state="DISABLED")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
        _wait_until(
            lambda: batch.describe_job_queues(jobQueues=[arn])["jobQueues"],
            lambda qs: not qs or qs[0]["status"] in ("VALID", "INVALID"),
        )
        # DeleteJobQueue is refused while the quota share's own deletion is still settling, and
        # the scheduling policy deleted after this is refused while the queue exists, so retry
        # the delete until the queue is gone.
        def _delete_and_check():
            batch.delete_job_queue(jobQueue=arn)
            return batch.describe_job_queues(jobQueues=[arn])["jobQueues"]

        _wait_until(
            _delete_and_check,
            lambda qs: not qs or qs[0]["status"] == "DELETED",
            timeout_s=240.0,
            interval_s=5.0,
        )

    ctx.on_cleanup(_cleanup)
    _wait_until(
        lambda: batch.describe_job_queues(jobQueues=[arn])["jobQueues"],
        lambda qs: qs and qs[0]["status"] in ("VALID", "INVALID"),
    )
    return name, arn


def _setup_quota_management_job_queue(ctx):
    sp_arn = _create_quota_scheduling_policy(ctx)
    se_name, se_arn = _create_sagemaker_service_environment(ctx)
    jq_name, jq_arn = _create_sagemaker_job_queue(ctx, sp_arn, se_name)
    return {
        "scheduling_policy_arn": sp_arn,
        "service_environment_arn": se_arn,
        "job_queue_name": jq_name,
        "job_queue_arn": jq_arn,
    }


def _create_quota_share(ctx, job_queue, name=None, max_capacity=1, strategy="RESERVE", in_share_preemption="DISABLED"):
    batch = ctx.client("batch")
    name = name or ctx.unique_name("sim2real-batch-qs-")
    arn = batch.create_quota_share(
        quotaShareName=name,
        jobQueue=job_queue,
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": max_capacity}],
        resourceSharingConfiguration={"strategy": strategy},
        preemptionConfiguration={"inSharePreemption": in_share_preemption},
        tags={"env": "sim2real-behav"},
    )["quotaShareArn"]

    def _cleanup():
        try:
            batch.update_quota_share(quotaShareArn=arn, state="DISABLED")
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
            ):
                raise
        try:
            _wait_quota_share_status(batch, arn, {"VALID", "INVALID"}, timeout_s=60.0)
        except AssertionError:
            pass
        batch.delete_quota_share(quotaShareArn=arn)

    ctx.on_cleanup(_cleanup)
    return arn


def _wait_quota_share_status(batch, arn, target_statuses, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = batch.describe_quota_share(quotaShareArn=arn)
        if last.get("status") in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"quota share {arn} did not reach {target_statuses}; last status={last.get('status') if last else None}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
