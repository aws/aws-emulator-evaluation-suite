"""delete-quota-share-while-enabled-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-quota-share-while-enabled-rejected"
GROUP = "state-machine"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteQuotaShare on an ENABLED quota share is refused with ClientException and the
    quota share is left intact; disabling it first (positive control) makes the delete
    succeed."""
    batch = ctx.client("batch")
    queue_arn = _create_sagemaker_training_queue(ctx)

    quota_name = ctx.unique_name("sim2real-qshare-")
    quota_arn = batch.create_quota_share(
        quotaShareName=quota_name,
        jobQueue=queue_arn,
        # Creating a QuotaShare against a service environment implicitly turns on
        # "quota management" for that environment, and real AWS Batch then requires the
        # QuotaShare's capacityLimits to be keyed by an actual SageMaker Training instance
        # type (e.g. "ml.m5.large") rather than the generic NUM_INSTANCES unit
        # (ClientException: "NUM_INSTANCES is not a valid SageMaker Training Instance
        # Type.") — so the backing service environment below is provisioned with a
        # matching ml.m5.large capacity limit too.
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 2}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        state="ENABLED",
        tags={"env": "sim2real-behav"},
    )["quotaShareArn"]

    def _cleanup():
        _best_effort(lambda: batch.delete_quota_share(quotaShareArn=quota_arn))

    ctx.on_cleanup(_cleanup)

    _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=quota_arn)["status"],
        lambda s: s in ("VALID", "INVALID"),
        timeout_s=120,
    )
    pre = batch.describe_quota_share(quotaShareArn=quota_arn)["state"]
    assert pre == "ENABLED", f"positive control: expected ENABLED, got {pre!r}"

    # Break exactly one precondition: try to delete while still ENABLED.
    code, message = _error_code(lambda: batch.delete_quota_share(quotaShareArn=quota_arn))
    assert code == "ClientException", f"expected ClientException, got {code!r}"
    expected = "Quota Share must be DISABLED before deleting."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The forbidden effect did not happen: the quota share still exists and is unchanged.
    still_there = batch.describe_quota_share(quotaShareArn=quota_arn)
    assert still_there["quotaShareName"] == quota_name, (
        f"expected quota share {quota_name!r} to still exist, got {still_there['quotaShareName']!r}"
    )
    assert still_there["state"] == "ENABLED", (
        f"expected rejected delete to leave state ENABLED, got {still_there['state']!r}"
    )

    # Positive control: fix the precondition (disable), then the same delete succeeds.
    batch.update_quota_share(quotaShareArn=quota_arn, state="DISABLED")
    _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=quota_arn)["state"],
        lambda s: s == "DISABLED",
        timeout_s=120,
    )
    batch.delete_quota_share(quotaShareArn=quota_arn)
    def _probe_gone():
        try:
            batch.describe_quota_share(quotaShareArn=quota_arn)
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")
        return "still-describable", None

    _, gone_message = _poll_until(_probe_gone, lambda r: r[0] == "ClientException", timeout_s=120)
    expected_gone = f"{quota_arn} does not exist."
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"


def _error_code(fn: Callable[[], Any]):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises AssertionError."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused with a ClientError, but it succeeded")


def _best_effort(fn: Callable[[], Any]) -> None:
    """Run a teardown step, ignoring a ClientError (the resource may already be gone)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_sagemaker_training_queue(ctx) -> str:
    """Real AWS Batch's CreateQuotaShare validates capacityLimits against the job queue's
    backing environment type; only a SAGEMAKER_TRAINING queue (backed by a service
    environment) accepts Quota Share. Once a QuotaShare is attached, the environment is
    "quota management enabled" and capacityUnit must be a real SageMaker Training instance
    type (e.g. "ml.m5.large"), not the generic NUM_INSTANCES unit."""
    batch = ctx.client("batch")

    env_name = ctx.unique_name("sim2real-svcenv-")
    env_arn = batch.create_service_environment(
        serviceEnvironmentName=env_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 4}],
        state="ENABLED",
        tags={"env": "sim2real-behav"},
    )["serviceEnvironmentArn"]

    def _cleanup_env():
        _best_effort(lambda: batch.update_service_environment(serviceEnvironment=env_arn, state="DISABLED"))
        _poll_until(
            lambda: batch.describe_service_environments(serviceEnvironments=[env_arn])["serviceEnvironments"][0]["status"],
            lambda s: s in ("VALID", "INVALID"),
            timeout_s=90,
        )
        _best_effort(lambda: batch.delete_service_environment(serviceEnvironment=env_arn))

    ctx.on_cleanup(_cleanup_env)
    _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[env_arn])["serviceEnvironments"][0]["status"],
        lambda s: s in ("VALID", "INVALID"),
        timeout_s=90,
    )

    # Real AWS Batch rejects CreateJobQueue for a queue backed by a quota-management
    # compatible service environment unless it references a quota share scheduling
    # policy (ClientException: "... requires a quota share scheduling policy."), so
    # create one and attach it via schedulingPolicyArn.
    policy_name = ctx.unique_name("sim2real-qspolicy-")
    policy_arn = batch.create_scheduling_policy(
        name=policy_name,
        # QuotaSharePolicy (unlike FairsharePolicy) has no shareDistribution member at
        # all; real AWS Batch rejects it as an unknown parameter. The only member is
        # the required idleResourceAssignmentStrategy, which selects how idle capacity
        # is assigned across quota shares. "LEND_AND_BORROW" is a value of the
        # *QuotaShare-level* resourceSharingConfiguration.strategy enum, not of this
        # scheduling-policy-level field; real AWS Batch rejects it here with
        # ClientException ("Idle resource assignment strategy must be one of [FIFO].").
        # The only valid value for the scheduling policy's idleResourceAssignmentStrategy
        # is "FIFO".
        quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"},
        tags={"env": "sim2real-behav"},
    )["arn"]

    def _cleanup_policy():
        _best_effort(lambda: batch.delete_scheduling_policy(arn=policy_arn))

    ctx.on_cleanup(_cleanup_policy)

    name = ctx.unique_name("sim2real-svcq-")
    arn = batch.create_job_queue(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        state="ENABLED",
        schedulingPolicyArn=policy_arn,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": env_arn}],
        tags={"env": "sim2real-behav"},
    )["jobQueueArn"]

    def _cleanup():
        _best_effort(lambda: batch.update_job_queue(jobQueue=arn, state="DISABLED"))
        _poll_until(
            lambda: batch.describe_job_queues(jobQueues=[arn])["jobQueues"][0]["status"],
            lambda s: s in ("VALID", "INVALID"),
            timeout_s=120,
        )
        batch.delete_job_queue(jobQueue=arn)

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[arn])["jobQueues"][0]["status"],
        lambda s: s in ("VALID", "INVALID"),
        timeout_s=120,
    )
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
