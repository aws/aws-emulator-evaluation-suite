"""update-service-job-terminal-state-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-service-job-terminal-state-rejected"
GROUP = "state-machine"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateServiceJob on an already-terminal service job is rejected; a non-terminal job still updates."""
    batch = ctx.client("batch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    queue_name = _setup_service_job_queue(ctx, batch, with_scheduling_policy=True)

    # --- break exactly one thing: terminate a job, then try to update it ---
    terminal_job_name = ctx.unique_name("sim2real-batch-svcjob-terminal-")
    terminal_job_id = _submit_stuck_service_job(
        batch,
        queue_name,
        terminal_job_name,
        account_id=account_id,
        scheduling_priority=1,
        share_identifier="sim2realshare",
    )
    _poll_until(
        lambda: batch.describe_service_job(jobId=terminal_job_id),
        lambda d: d["status"] in ("PENDING", "RUNNABLE", "SCHEDULED"),
        timeout_s=90,
    )
    batch.terminate_service_job(jobId=terminal_job_id, reason="make terminal for negative test")
    _poll_until(
        lambda: batch.describe_service_job(jobId=terminal_job_id),
        lambda d: d["status"] in ("SUCCEEDED", "FAILED"),
        timeout_s=90,
    )

    code, message = _error_code(lambda: batch.update_service_job(jobId=terminal_job_id, schedulingPriority=9))
    assert code == "ClientException", f"expected ClientException updating a terminal service job, got {code!r}"
    expected = "UpdateServiceJob cannot be called on a service job which is completed."
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # effect absent: schedulingPriority must not have changed on the terminal job
    unchanged = batch.describe_service_job(jobId=terminal_job_id)
    assert unchanged["schedulingPriority"] == 1, (
        f"rejected update must not have applied; expected schedulingPriority 1, got {unchanged['schedulingPriority']}"
    )
    assert unchanged["status"] == "FAILED", f"expected job to remain FAILED, got {unchanged['status']}"

    # --- positive control: the exact same update succeeds on a non-terminal job ---
    live_job_name = ctx.unique_name("sim2real-batch-svcjob-live-")
    live_job_id = _submit_stuck_service_job(
        batch,
        queue_name,
        live_job_name,
        account_id=account_id,
        scheduling_priority=1,
        share_identifier="sim2realshare",
    )
    ctx.on_cleanup(lambda: _best_effort_terminate(batch, live_job_id))
    _poll_until(
        lambda: batch.describe_service_job(jobId=live_job_id),
        lambda d: d["status"] in ("PENDING", "RUNNABLE", "SCHEDULED"),
        timeout_s=90,
    )
    batch.update_service_job(jobId=live_job_id, schedulingPriority=9)
    updated = _poll_until(
        lambda: batch.describe_service_job(jobId=live_job_id),
        lambda d: d["schedulingPriority"] == 9,
        timeout_s=60,
    )
    assert updated["schedulingPriority"] == 9, (
        f"expected the identical update to succeed on a non-terminal job; "
        f"got schedulingPriority {updated['schedulingPriority']}"
    )


def _error_code(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _best_effort_terminate(batch, job_id) -> None:
    batch.terminate_service_job(jobId=job_id, reason="sim2real behavioral test cleanup")


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


def _delete_scheduling_policy(batch, policy_arn) -> None:
    batch.delete_scheduling_policy(arn=policy_arn)


def _setup_service_job_queue(ctx, batch, with_scheduling_policy=False) -> str:
    """Create a SAGEMAKER_TRAINING service environment (1-instance cap) and job queue; return the queue name."""
    env_name = ctx.unique_name("sim2real-batch-svcenv-")
    batch.create_service_environment(
        serviceEnvironmentName=env_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "NUM_INSTANCES", "maxCapacity": 1}],
    )
    ctx.on_cleanup(lambda: _disable_and_delete_service_environment(batch, env_name))
    _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[env_name])["serviceEnvironments"][0],
        lambda e: e["status"] == "VALID",
        timeout_s=120,
    )

    create_kwargs = {
        "jobQueueName": ctx.unique_name("sim2real-batch-svcq-"),
        "jobQueueType": "SAGEMAKER_TRAINING",
        "priority": 1,
        "serviceEnvironmentOrder": [{"order": 1, "serviceEnvironment": env_name}],
    }
    queue_name = create_kwargs["jobQueueName"]

    if with_scheduling_policy:
        # schedulingPriority on SubmitServiceJob is only accepted by a queue backed by a
        # fair-share scheduling policy — attach one so the update-priority check is valid.
        policy_name = ctx.unique_name("sim2real-batch-svcpolicy-")
        policy_resp = batch.create_scheduling_policy(
            name=policy_name,
            fairsharePolicy={"computeReservation": 0, "shareDecaySeconds": 0, "shareDistribution": []},
        )
        policy_arn = policy_resp["arn"]
        ctx.on_cleanup(lambda: _delete_scheduling_policy(batch, policy_arn))
        create_kwargs["schedulingPolicyArn"] = policy_arn

    batch.create_job_queue(**create_kwargs)
    ctx.on_cleanup(lambda: _disable_and_delete_job_queue(batch, queue_name))
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[queue_name])["jobQueues"][0],
        lambda q: q["status"] == "VALID",
        timeout_s=120,
    )
    return queue_name


def _submit_stuck_service_job(
    batch, queue_name, job_name, account_id, scheduling_priority=1, share_identifier=None
) -> str:
    """Submit a service job that requests more instances than the environment can ever grant.

    This guarantees the job stays queued (never reaches STARTING/RUNNING against the real
    SageMaker Training API) so the check never incurs real training-job compute cost.
    """
    payload = json.dumps(
        {
            "TrainingJobName": job_name,
            "RoleArn": f"arn:aws:iam::{account_id}:role/sim2real-nonexistent-execution-role",
            "AlgorithmSpecification": {
                "TrainingInputMode": "File",
                "TrainingImage": "123456789012.dkr.ecr.us-east-1.amazonaws.com/pytorch-training:1.8.0-cpu-py3",
                "ContainerEntrypoint": ["sleep", "1"],
            },
            "ResourceConfig": {"InstanceType": "ml.m5.large", "InstanceCount": 5, "VolumeSizeInGB": 1},
            "OutputDataConfig": {"S3OutputPath": "s3://sim2real-batch-nonexistent-bucket/output"},
            "StoppingCondition": {"MaxRuntimeInSeconds": 60},
        }
    )
    kwargs = {
        "jobName": job_name,
        "jobQueue": queue_name,
        "serviceJobType": "SAGEMAKER_TRAINING",
        "serviceRequestPayload": payload,
        "schedulingPriority": scheduling_priority,
    }
    if share_identifier:
        kwargs["shareIdentifier"] = share_identifier
    resp = batch.submit_service_job(**kwargs)
    return resp["jobId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


