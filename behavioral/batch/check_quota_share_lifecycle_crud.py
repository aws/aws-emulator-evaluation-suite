"""quota-share-lifecycle-crud."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "quota-share-lifecycle-crud"
GROUP = "state-machine"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateQuotaShare produces a resource DescribeQuotaShare returns; UpdateQuotaShare
    mutates its share weight (borrowLimit); DeleteQuotaShare removes it permanently."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    batch = ctx.client("batch")

    queue_arn = _create_sagemaker_training_queue(ctx, teardown_deadline)

    quota_name = ctx.unique_name("sim2real-qshare-")
    create_resp = batch.create_quota_share(
        quotaShareName=quota_name,
        jobQueue=queue_arn,
        # Creating a QuotaShare against a service environment implicitly turns on
        # "quota management" for that environment, and real AWS Batch then requires the
        # QuotaShare's capacityLimits to be keyed by an actual SageMaker Training instance
        # type (e.g. "ml.m5.large") rather than the generic NUM_INSTANCES unit
        # (ClientException: "NUM_INSTANCES is not a valid SageMaker Training Instance
        # Type.") — so the backing service environment above is provisioned with a
        # matching ml.m5.large capacity limit too.
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 4}],
        resourceSharingConfiguration={"strategy": "LEND_AND_BORROW", "borrowLimit": 50},
        preemptionConfiguration={"inSharePreemption": "ENABLED"},
        state="ENABLED",
        tags={"sim2real": "true"},
    )
    quota_arn = create_resp["quotaShareArn"]
    assert create_resp["quotaShareName"] == quota_name, (
        f"expected quotaShareName {quota_name!r}, got {create_resp['quotaShareName']!r}"
    )

    def _cleanup_delete():
        try:
            batch.delete_quota_share(quotaShareArn=quota_arn)
        except ClientError as err:
            # Already deleted by the check body: DescribeQuotaShare confirms it is gone.
            if err.response["Error"]["Code"] != "ClientException":
                raise AssertionError(f"unexpected cleanup error deleting quota share: {err}") from err
            gone = _client_error(lambda: batch.describe_quota_share(quotaShareArn=quota_arn))
            if gone != ("ClientException", f"{quota_arn} does not exist."):
                raise AssertionError(f"quota share {quota_arn} not deleted: {err}; describe: {gone}") from err

    ctx.on_cleanup(_cleanup_delete)

    described = _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=quota_arn),
        lambda d: d["status"] in ("VALID", "INVALID"),
        timeout_s=120,
    )
    assert described["status"] == "VALID", f"quota share became {described['status']}"
    assert described["quotaShareName"] == quota_name, (
        f"expected quotaShareName {quota_name!r}, got {described['quotaShareName']!r}"
    )
    assert described["jobQueueArn"] == queue_arn, (
        f"expected jobQueueArn {queue_arn!r}, got {described['jobQueueArn']!r}"
    )
    assert described["resourceSharingConfiguration"]["borrowLimit"] == 50, (
        f"expected borrowLimit 50, got {described['resourceSharingConfiguration']['borrowLimit']!r}"
    )
    assert described["state"] == "ENABLED", f"expected state ENABLED, got {described['state']!r}"

    # UpdateQuotaShare mutates the share's borrow limit ("share weight").
    batch.update_quota_share(
        quotaShareArn=quota_arn,
        resourceSharingConfiguration={"strategy": "LEND_AND_BORROW", "borrowLimit": 275},
    )
    updated = _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=quota_arn),
        lambda d: d["status"] == "VALID" and d["resourceSharingConfiguration"]["borrowLimit"] == 275,
        timeout_s=120,
    )
    assert updated["resourceSharingConfiguration"]["borrowLimit"] == 275, (
        f"expected borrowLimit 275, got {updated['resourceSharingConfiguration']['borrowLimit']!r}"
    )

    # Must disable before delete is accepted (AWS enforces this precondition).
    batch.update_quota_share(quotaShareArn=quota_arn, state="DISABLED")
    _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=quota_arn),
        lambda d: d["status"] == "VALID" and d["state"] == "DISABLED",
        timeout_s=120,
    )

    batch.delete_quota_share(quotaShareArn=quota_arn)
    code, message = _client_error(lambda: batch.describe_quota_share(quotaShareArn=quota_arn), wait_s=120, interval_s=3.0)
    assert code == "ClientException", f"expected ClientException describing a deleted quota share, got {code!r}"
    expected = f"{quota_arn} does not exist."
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # Gone is not just unreadable — a mutation against the dead id fails the same way.
    mutate_code, mutate_message = _client_error(
        lambda: batch.update_quota_share(quotaShareArn=quota_arn, state="ENABLED")
    )
    assert mutate_code == "ClientException", (
        f"expected ClientException updating a deleted quota share, got {mutate_code!r}"
    )
    assert mutate_message == expected, f"expected {expected!r}, got {mutate_message!r}"


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


def _ignore_client_error(fn: Callable[[], Any]) -> None:
    """Teardown step: run fn(), ignoring a ClientError (the resource may already be gone)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


# budget.cleanup_timeout for behavioral/batch, one deadline shared by every teardown of a run.
_TEARDOWN_RETRY_S = 900.0


def _teardown_deadline(teardown_deadline) -> float:
    return teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 120.0)


def _retry_relationship(fn: Callable[[], Any], teardown_deadline) -> None:
    """Teardown step: retry fn() every 2 s while AWS refuses it with the ClientException that
    a job queue still references the resource, to the cleanup deadline; raise everything else."""
    deadline = _teardown_deadline(teardown_deadline)
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response["Error"]
            linked = err["Code"] == "ClientException" and err.get("Message", "").startswith(
                "Cannot delete, found existing JobQueue relationship"
            )
            if not linked or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_sagemaker_training_queue(ctx, teardown_deadline) -> str:
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
        tags={"sim2real": "true"},
    )["serviceEnvironmentArn"]

    def _cleanup_env():
        _ignore_client_error(lambda: batch.update_service_environment(serviceEnvironment=env_arn, state="DISABLED"))
        _poll_until(
            lambda: batch.describe_service_environments(serviceEnvironments=[env_arn])["serviceEnvironments"][0]["status"],
            lambda s: s in ("VALID", "INVALID"),
            timeout_s=90,
        )
        _retry_relationship(lambda: _ignore_client_error(
            lambda: batch.delete_service_environment(serviceEnvironment=env_arn)), teardown_deadline)

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
        tags={"sim2real": "true"},
    )["arn"]

    def _cleanup_policy():
        _retry_relationship(
            lambda: _ignore_client_error(lambda: batch.delete_scheduling_policy(arn=policy_arn)), teardown_deadline
        )

    ctx.on_cleanup(_cleanup_policy)

    name = ctx.unique_name("sim2real-svcq-")
    arn = batch.create_job_queue(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        state="ENABLED",
        schedulingPolicyArn=policy_arn,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": env_arn}],
        tags={"sim2real": "true"},
    )["jobQueueArn"]

    def _cleanup():
        # A queue still CREATING/UPDATING refuses the disable, so wait for it to settle first.
        _poll_until(
            lambda: batch.describe_job_queues(jobQueues=[arn])["jobQueues"],
            lambda qs: not qs or qs[0]["status"] in ("VALID", "INVALID", "DELETED"),
            timeout_s=max(_teardown_deadline(teardown_deadline) - time.monotonic(), 1.0),
            interval_s=2.0,
        )
        _ignore_client_error(lambda: batch.update_job_queue(jobQueue=arn, state="DISABLED"))
        _poll_until(
            lambda: batch.describe_job_queues(jobQueues=[arn])["jobQueues"][0],
            lambda q: q["state"] == "DISABLED" and q["status"] in ("VALID", "INVALID"),
            timeout_s=120,
        )
        batch.delete_job_queue(jobQueue=arn)
        # The delete is asynchronous; the policy and environment refuse deletion until it is gone.
        _poll_until(
            lambda: batch.describe_job_queues(jobQueues=[arn])["jobQueues"],
            lambda qs: not qs or qs[0]["status"] == "DELETED",
            timeout_s=max(_teardown_deadline(teardown_deadline) - time.monotonic(), 1.0),
            interval_s=2.0,
        )

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
