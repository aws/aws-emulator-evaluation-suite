"""update-service-job-terminal-state-blocked."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-service-job-terminal-state-blocked"
GROUP = "overly-permissive"
SERVICES = ["batch"]

_TERMINAL = {"SUCCEEDED", "FAILED"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateServiceJob is rejected once TerminateServiceJob has moved the job to a terminal state."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    batch = ctx.client("batch")
    se = _create_service_environment(ctx, teardown_deadline)
    policy_arn = _create_scheduling_policy(ctx, teardown_deadline)
    jq = _create_job_queue(ctx, se["name"], teardown_deadline, scheduling_policy_arn=policy_arn)

    # Job A: submitted then terminated -> reaches a terminal state.
    job_a = _submit_service_job(ctx, jq["name"], scheduling_priority=1)
    batch.terminate_service_job(jobId=job_a["jobId"], reason="sim2real-terminal-precondition")
    described_a = _poll_until(
        lambda: batch.describe_service_job(jobId=job_a["jobId"]),
        lambda d: d["status"] in _TERMINAL,
        timeout_s=120,
    )
    assert described_a["status"] == "FAILED", f"expected FAILED after TerminateServiceJob, got {described_a['status']}"
    assert described_a["schedulingPriority"] == 1, f"expected schedulingPriority 1, got {described_a['schedulingPriority']}"

    def _update_terminal():
        batch.update_service_job(jobId=job_a["jobId"], schedulingPriority=9)

    code, message = _error_code(_update_terminal)
    assert code == "ClientException", f"expected ClientException, got {code}"
    expected = "UpdateServiceJob cannot be called on a service job which is completed."
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # Effect absent: priority unchanged after the rejected update.
    after = batch.describe_service_job(jobId=job_a["jobId"])
    assert after["schedulingPriority"] == 1, f"rejected update must not have applied; expected 1, got {after['schedulingPriority']}"

    # Positive control: a non-terminal job's priority CAN be updated.
    job_b = _submit_service_job(ctx, jq["name"], scheduling_priority=1)
    ctx.on_cleanup(lambda: _terminate_quietly(ctx, job_b["jobId"]))
    updated = batch.update_service_job(jobId=job_b["jobId"], schedulingPriority=5)
    assert updated["jobId"] == job_b["jobId"], f"expected jobId {job_b['jobId']}, got {updated['jobId']}"
    described_b = batch.describe_service_job(jobId=job_b["jobId"])
    assert described_b["schedulingPriority"] == 5, f"expected updated schedulingPriority 5, got {described_b['schedulingPriority']}"


def _error_code(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS refuses must not be reported as an
    error-code mismatch downstream."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientException, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _create_service_environment(ctx, teardown_deadline):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-se-")
    batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"maxCapacity": 1, "capacityUnit": "NUM_INSTANCES"}],
        tags={"env": "sim2real-behav"},
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
    resp = batch.create_scheduling_policy(
        name=name,
        fairsharePolicy={"computeReservation": 0, "shareDecaySeconds": 0, "shareDistribution": []},
        tags={"env": "sim2real-behav"},
    )
    arn = resp["arn"]
    ctx.on_cleanup(lambda: _delete_scheduling_policy_quietly(ctx, arn, teardown_deadline))
    return arn


def _delete_scheduling_policy_quietly(ctx, arn, teardown_deadline):
    _retry_in_use(ctx, lambda: ctx.client("batch").delete_scheduling_policy(arn=arn), teardown_deadline)


def _create_job_queue(ctx, service_environment_name, teardown_deadline, scheduling_policy_arn, priority=1):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-jq-")
    batch.create_job_queue(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=priority,
        schedulingPolicyArn=scheduling_policy_arn,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": service_environment_name}],
        tags={"env": "sim2real-behav"},
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


def _submit_service_job(ctx, job_queue_name, scheduling_priority=1, instance_count=1):
    batch = ctx.client("batch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    job_name = ctx.unique_name("sim2real-batch-sj-")
    payload = {
        "TrainingJobName": job_name,
        "RoleArn": f"arn:aws:iam::{account_id}:role/sim2real-nonexistent-sagemaker-role",
        "AlgorithmSpecification": {
            "TrainingInputMode": "File",
            "TrainingImage": "123456789012.dkr.ecr.us-west-2.amazonaws.com/pytorch-training:2.0.0-cpu-py310",
            "ContainerEntrypoint": ["echo", "hello"],
        },
        "ResourceConfig": {
            "InstanceType": "ml.m5.large",
            "InstanceCount": instance_count,
            "VolumeSizeInGB": 1,
        },
        "OutputDataConfig": {"S3OutputPath": f"s3://sim2real-nonexistent-bucket/{job_name}/"},
        "StoppingCondition": {"MaxRuntimeInSeconds": 30},
    }
    resp = batch.submit_service_job(
        jobName=job_name,
        jobQueue=job_queue_name,
        serviceJobType="SAGEMAKER_TRAINING",
        serviceRequestPayload=json.dumps(payload),
        schedulingPriority=scheduling_priority,
        shareIdentifier="sim2realshare",
        tags={"env": "sim2real-behav"},
    )
    return {"jobId": resp["jobId"], "jobName": job_name}


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
