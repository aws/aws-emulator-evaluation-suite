"""service-job-numeric-parameters-precision-preserved."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "service-job-numeric-parameters-precision-preserved"
GROUP = "representation"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Numeric fields and an omitted optional field on SubmitServiceJob come back unchanged."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    batch = ctx.client("batch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    # Real AWS Batch rejects SubmitServiceJob's schedulingPriority outright ("Job with
    # shareIdentifier or schedulingPriority can only be submitted to job queue with fair
    # share scheduling policy") unless the queue carries a scheduling policy -- and a
    # fair-share policy in turn requires every job on that queue to carry a shareIdentifier.
    # So schedulingPriority and an unconditionally-omitted shareIdentifier
    # cannot coexist, so shareIdentifier is supplied and its round trip asserted instead;
    # quotaShareName (unrelated to a fair-share policy) stays the omitted-field case.
    policy_arn = _create_scheduling_policy(ctx, teardown_deadline)
    se = _create_service_environment(ctx, teardown_deadline, max_capacity=1)
    jq = _create_job_queue(ctx, se["name"], teardown_deadline, scheduling_policy_arn=policy_arn)

    job_name = ctx.unique_name("sim2real-batch-sj-num-")
    payload = {
        "TrainingJobName": job_name,
        "RoleArn": f"arn:aws:iam::{account_id}:role/sim2real-nonexistent-sagemaker-role",
        "AlgorithmSpecification": {
            "TrainingInputMode": "File",
            "TrainingImage": f"123456789012.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-training:2.0.0-cpu-py310",
            "ContainerEntrypoint": ["echo", "hello"],
        },
        "ResourceConfig": {
            "InstanceType": "ml.m5.large",
            "InstanceCount": 2,  # exceeds the service environment's capacity of 1 -> stays RUNNABLE
            "VolumeSizeInGB": 13,
        },
        "OutputDataConfig": {"S3OutputPath": f"s3://sim2real-nonexistent-bucket/{job_name}/"},
        "StoppingCondition": {"MaxRuntimeInSeconds": 45},
    }
    payload_str = json.dumps(payload)

    share_identifier = "default"
    # quotaShareName is intentionally omitted: it belongs to a quotaSharePolicy, not the
    # fairsharePolicy this queue carries, so it must stay unset regardless of shareIdentifier.
    resp = batch.submit_service_job(
        jobName=job_name,
        jobQueue=jq["name"],
        serviceJobType="SAGEMAKER_TRAINING",
        serviceRequestPayload=payload_str,
        schedulingPriority=17,
        shareIdentifier=share_identifier,
        timeoutConfig={"attemptDurationSeconds": 999},
        retryStrategy={"attempts": 1},
        tags=_MANAGED_TAGS,
    )
    job_id = resp["jobId"]
    ctx.on_cleanup(lambda: _terminate_quietly(ctx, job_id))

    described = _poll_until(
        lambda: batch.describe_service_job(jobId=job_id),
        lambda d: d["status"] == "RUNNABLE",
        timeout_s=120,
    )

    assert described["schedulingPriority"] == 17, (
        f"schedulingPriority: expected 17, got {described['schedulingPriority']!r}"
    )
    assert described["timeoutConfig"]["attemptDurationSeconds"] == 999, (
        "timeoutConfig.attemptDurationSeconds: expected 999, got "
        f"{described['timeoutConfig']['attemptDurationSeconds']!r}"
    )
    assert described["retryStrategy"]["attempts"] == 1, (
        f"retryStrategy.attempts: expected 1, got {described['retryStrategy']['attempts']!r}"
    )
    assert described["serviceRequestPayload"] == payload_str, "serviceRequestPayload was not byte-identical"

    round_tripped = json.loads(described["serviceRequestPayload"])
    assert round_tripped["ResourceConfig"]["VolumeSizeInGB"] == 13, (
        "ResourceConfig.VolumeSizeInGB: expected 13, got "
        f"{round_tripped['ResourceConfig']['VolumeSizeInGB']!r}"
    )
    assert round_tripped["ResourceConfig"]["InstanceCount"] == 2, (
        "ResourceConfig.InstanceCount: expected 2, got "
        f"{round_tripped['ResourceConfig']['InstanceCount']!r}"
    )
    assert round_tripped["StoppingCondition"]["MaxRuntimeInSeconds"] == 45, (
        "StoppingCondition.MaxRuntimeInSeconds: expected 45, got "
        f"{round_tripped['StoppingCondition']['MaxRuntimeInSeconds']!r}"
    )

    assert described.get("shareIdentifier") == share_identifier, (
        f"shareIdentifier: expected {share_identifier!r}, got {described.get('shareIdentifier')!r}"
    )
    # An optional field that was never supplied must come back absent/None, not defaulted.
    assert described.get("quotaShareName") is None, (
        f"quotaShareName: expected absent/None, got {described.get('quotaShareName')!r}"
    )


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _create_service_environment(ctx, teardown_deadline, max_capacity=1):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-se-")
    batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"maxCapacity": max_capacity, "capacityUnit": "NUM_INSTANCES"}],
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _teardown_service_environment(ctx, name, teardown_deadline))
    _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0],
        lambda se: se["status"] == "VALID",
        timeout_s=90,
    )
    return {"name": name}


def _teardown_service_environment(ctx, name, teardown_deadline):
    batch = ctx.client("batch")
    try:
        batch.update_service_environment(serviceEnvironment=name, state="DISABLED")
        _poll_until(
            lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0],
            lambda se: se["state"] == "DISABLED" and se["status"] == "VALID",
            timeout_s=90,
        )
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    _retry_in_use(ctx, lambda: batch.delete_service_environment(serviceEnvironment=name), teardown_deadline)


def _create_scheduling_policy(ctx, teardown_deadline):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")
    arn = batch.create_scheduling_policy(
        name=name,
        fairsharePolicy={"computeReservation": 0, "shareDecaySeconds": 0, "shareDistribution": []},
        tags=_MANAGED_TAGS,
    )["arn"]
    ctx.on_cleanup(lambda: _delete_quietly(lambda: _retry_in_use(
        ctx, lambda: batch.delete_scheduling_policy(arn=arn), teardown_deadline)))
    return arn


def _delete_quietly(fn):
    fn()


def _create_job_queue(ctx, service_environment_name, teardown_deadline, scheduling_policy_arn, priority=1):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-jq-")
    batch.create_job_queue(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=priority,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": service_environment_name}],
        schedulingPolicyArn=scheduling_policy_arn,
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _teardown_job_queue(ctx, name, teardown_deadline))
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"][0],
        lambda jq: jq["status"] == "VALID",
        timeout_s=90,
    )
    return {"name": name}


def _teardown_job_queue(ctx, name, teardown_deadline):
    batch = ctx.client("batch")
    try:
        batch.update_job_queue(jobQueue=name, state="DISABLED")
        _poll_until(
            lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"][0],
            lambda jq: jq["state"] == "DISABLED" and jq["status"] == "VALID",
            timeout_s=90,
        )
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    _retry_in_use(ctx, lambda: batch.delete_job_queue(jobQueue=name), teardown_deadline)


def _terminate_quietly(ctx, job_id):
    ctx.client("batch").terminate_service_job(jobId=job_id, reason="sim2real-cleanup")


#: The suite's cleanup budget; the retries of every teardown of one run share one deadline in it.
_CLEANUP_BUDGET_S = 900.0


def _retry_in_use(ctx, delete, teardown_deadline) -> None:
    """Run a Batch delete, retrying the "found existing ... relationship" refusal every 2 s to the
    run's cleanup deadline while a dependent finishes deleting; "does not exist" is gone."""
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _CLEANUP_BUDGET_S)
    while True:
        try:
            delete()
            return
        except ClientError as err:
            e = err.response["Error"]
            if e["Code"] == "ClientException" and "does not exist" in e.get("Message", ""):
                return
            in_use = e["Code"] == "ClientException" and "found existing" in e.get("Message", "")
            if not in_use or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
