"""service-job-terminate-terminal-is-idempotent."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-job-terminate-terminal-is-idempotent"
GROUP = "state-machine"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Calling TerminateServiceJob again on an already-terminal job is accepted and status is unchanged."""
    batch = ctx.client("batch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    queue_name = _setup_service_job_queue(ctx, batch)

    job_name = ctx.unique_name("sim2real-batch-svcjob-")
    job_id = _submit_stuck_service_job(batch, queue_name, job_name, account_id=account_id)

    _poll_until(
        lambda: batch.describe_service_job(jobId=job_id),
        lambda d: d["status"] in ("PENDING", "RUNNABLE", "SCHEDULED"),
        timeout_s=90,
    )

    batch.terminate_service_job(jobId=job_id, reason="first termination")
    first_terminal = _poll_until(
        lambda: batch.describe_service_job(jobId=job_id),
        lambda d: d["status"] in ("SUCCEEDED", "FAILED"),
        timeout_s=90,
    )
    assert first_terminal["status"] == "FAILED", (
        f"expected first terminate to force FAILED, got {first_terminal['status']!r}"
    )

    # second call on an already-terminal job must be accepted, not rejected: no exception
    # propagating out of this call is itself part of the assertion.
    batch.terminate_service_job(jobId=job_id, reason="second termination on terminal job")

    second_described = batch.describe_service_job(jobId=job_id)
    assert second_described["status"] == "FAILED", "terminal status must not change on repeat terminate"
    assert second_described.get("isTerminated") is True, (
        f"expected isTerminated=True after repeat terminate, got {second_described.get('isTerminated')!r}"
    )
    assert second_described.get("statusReason") == first_terminal.get("statusReason"), (
        "redundant terminate call must not overwrite the statusReason recorded by the first call: "
        f"first={first_terminal.get('statusReason')!r} second={second_described.get('statusReason')!r}"
    )


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


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


def _setup_service_job_queue(ctx, batch) -> str:
    """Create a SAGEMAKER_TRAINING service environment (1-instance cap) and job queue; return the queue name."""
    env_name = ctx.unique_name("sim2real-batch-svcenv-")
    batch.create_service_environment(
        serviceEnvironmentName=env_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "NUM_INSTANCES", "maxCapacity": 1}],
        tags={"sim2real": "true"},
    )
    ctx.on_cleanup(lambda: _disable_and_delete_service_environment(batch, env_name))
    _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[env_name])["serviceEnvironments"][0],
        lambda e: e["status"] == "VALID",
        timeout_s=120,
    )

    queue_name = ctx.unique_name("sim2real-batch-svcq-")
    batch.create_job_queue(
        jobQueueName=queue_name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
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


def _submit_stuck_service_job(batch, queue_name, job_name, account_id) -> str:
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
    resp = batch.submit_service_job(
        jobName=job_name,
        jobQueue=queue_name,
        serviceJobType="SAGEMAKER_TRAINING",
        serviceRequestPayload=payload,
    )
    return resp["jobId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
