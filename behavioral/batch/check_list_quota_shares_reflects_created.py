"""list-quota-shares-reflects-created."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-quota-shares-reflects-created"
GROUP = "state-machine"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real": CHECK}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListQuotaShares includes a newly created quota share and no longer returns it
    after deletion."""
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
        capacityLimits=[{"capacityUnit": "ml.m5.large", "maxCapacity": 4}],
        resourceSharingConfiguration={"strategy": "RESERVE"},
        preemptionConfiguration={"inSharePreemption": "DISABLED"},
        tags=_MANAGED_TAGS,
    )["quotaShareArn"]

    def _cleanup():
        _ignore_client_error(lambda: batch.delete_quota_share(quotaShareArn=quota_arn))

    ctx.on_cleanup(_cleanup)

    _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=quota_arn)["status"],
        lambda s: s in ("VALID", "INVALID"),
        timeout_s=120,
    )

    names_before = _poll_until(
        lambda: {q["quotaShareName"] for q in _list_all_quota_shares(batch, queue_arn)},
        lambda names: quota_name in names,
        timeout_s=90,
    )
    assert quota_name in names_before, f"expected {quota_name!r} in ListQuotaShares, got {names_before!r}"

    matching = [q for q in _list_all_quota_shares(batch, queue_arn) if q["quotaShareName"] == quota_name]
    assert len(matching) == 1, f"expected exactly 1 entry named {quota_name!r}, got {len(matching)}: {matching!r}"
    assert matching[0]["quotaShareArn"] == quota_arn, (
        f"expected listed quotaShareArn {quota_arn!r}, got {matching[0]['quotaShareArn']!r}"
    )

    batch.update_quota_share(quotaShareArn=quota_arn, state="DISABLED")
    _poll_until(
        lambda: batch.describe_quota_share(quotaShareArn=quota_arn)["state"],
        lambda s: s == "DISABLED",
        timeout_s=120,
    )
    batch.delete_quota_share(quotaShareArn=quota_arn)

    names_after = _poll_until(
        lambda: {q["quotaShareName"] for q in _list_all_quota_shares(batch, queue_arn)},
        lambda names: quota_name not in names,
        timeout_s=120,
    )
    assert quota_name not in names_after, f"expected {quota_name!r} absent from ListQuotaShares after delete, got {names_after!r}"


def _ignore_client_error(fn: Callable[[], Any]) -> None:
    """Best-effort teardown step: a ClientError (already gone or already disabled) is ignored."""
    from botocore.exceptions import ClientError

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


def _list_all_quota_shares(batch, job_queue: str):
    out = []
    token = None
    while True:
        kwargs = {"jobQueue": job_queue}
        if token:
            kwargs["nextToken"] = token
        resp = batch.list_quota_shares(**kwargs)
        out.extend(resp.get("quotaShares", []))
        token = resp.get("nextToken")
        if not token:
            return out


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
        tags=_MANAGED_TAGS,
    )["serviceEnvironmentArn"]

    def _cleanup_env():
        _ignore_client_error(lambda: batch.update_service_environment(serviceEnvironment=env_arn, state="DISABLED"))
        _poll_until(
            lambda: batch.describe_service_environments(serviceEnvironments=[env_arn])["serviceEnvironments"][0]["status"],
            lambda s: s in ("VALID", "INVALID"),
            timeout_s=90,
        )
        _ignore_client_error(lambda: batch.delete_service_environment(serviceEnvironment=env_arn))

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
        tags=_MANAGED_TAGS,
    )["arn"]

    def _cleanup_policy():
        _ignore_client_error(lambda: batch.delete_scheduling_policy(arn=policy_arn))

    ctx.on_cleanup(_cleanup_policy)

    name = ctx.unique_name("sim2real-svcq-")
    arn = batch.create_job_queue(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        state="ENABLED",
        schedulingPolicyArn=policy_arn,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": env_arn}],
        tags=_MANAGED_TAGS,
    )["jobQueueArn"]

    def _cleanup():
        _ignore_client_error(lambda: batch.update_job_queue(jobQueue=arn, state="DISABLED"))
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
