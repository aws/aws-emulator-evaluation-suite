"""job-queue-snapshot-includes-service-job-entries."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "job-queue-snapshot-includes-service-job-entries"
GROUP = "data-plane"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch"}


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetJobQueueSnapshot lists an in-flight (RUNNABLE) service job and drops it once terminal."""
    batch = ctx.client("batch")
    se = _create_service_environment(ctx, max_capacity=1)
    jq = _create_job_queue(ctx, se["name"])

    # Request more instances than the service environment can ever provide, so the job stays
    # RUNNABLE (blocked on capacity) deterministically, without racing a real training run.
    job = _submit_service_job(ctx, jq["name"], instance_count=2)
    ctx.on_cleanup(lambda: _terminate_quietly(ctx, job["jobId"]))

    described = _poll_until(
        lambda: batch.describe_service_job(jobId=job["jobId"]),
        lambda d: d["status"] == "RUNNABLE",
        timeout_s=120,
    )
    assert described["status"] == "RUNNABLE", f"expected job stuck RUNNABLE, got {described['status']}"
    job_arn = described["jobArn"]

    snapshot = _poll_until(
        lambda: batch.get_job_queue_snapshot(jobQueue=jq["name"]),
        lambda s: any(j.get("jobArn") == job_arn for j in s.get("frontOfQueue", {}).get("jobs", [])),
        timeout_s=90,
    )
    front_arns = [j["jobArn"] for j in snapshot["frontOfQueue"]["jobs"]]
    assert job_arn in front_arns, f"expected RUNNABLE service job {job_arn} in frontOfQueue, got {front_arns!r}"

    # Move the job to a terminal state and confirm the snapshot entry disappears.
    batch.terminate_service_job(jobId=job["jobId"], reason="sim2real-observe-terminal")
    _poll_until(
        lambda: batch.describe_service_job(jobId=job["jobId"]),
        lambda d: d["status"] in {"FAILED", "SUCCEEDED"},
        timeout_s=120,
    )
    final_snapshot = _poll_until(
        lambda: batch.get_job_queue_snapshot(jobQueue=jq["name"]),
        lambda s: not any(j.get("jobArn") == job_arn for j in s.get("frontOfQueue", {}).get("jobs", [])),
        timeout_s=90,
    )
    final_arns = [j["jobArn"] for j in final_snapshot["frontOfQueue"]["jobs"]]
    assert job_arn not in final_arns, f"expected terminal service job {job_arn} dropped from frontOfQueue, got {final_arns!r}"


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _create_service_environment(ctx, max_capacity=1):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-se-")
    batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"maxCapacity": max_capacity, "capacityUnit": "NUM_INSTANCES"}],
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _teardown_service_environment(ctx, name))
    _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0],
        lambda se: se["status"] == "VALID",
        timeout_s=90,
    )
    return {"name": name}


def _teardown_service_environment(ctx, name):
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
    _retry_delete(lambda: batch.delete_service_environment(serviceEnvironment=name))


def _create_job_queue(ctx, service_environment_name, priority=1):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-jq-")
    batch.create_job_queue(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=priority,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": service_environment_name}],
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _teardown_job_queue(ctx, name))
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[name])["jobQueues"][0],
        lambda jq: jq["status"] == "VALID",
        timeout_s=90,
    )
    return {"name": name}


def _teardown_job_queue(ctx, name):
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
    _retry_delete(lambda: batch.delete_job_queue(jobQueue=name))
    _wait_jq_gone(batch, name)


def _submit_service_job(ctx, job_queue_name, instance_count=1):
    batch = ctx.client("batch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    job_name = ctx.unique_name("sim2real-batch-sj-")
    payload = {
        "TrainingJobName": job_name,
        "RoleArn": f"arn:aws:iam::{account_id}:role/sim2real-nonexistent-sagemaker-role",
        "AlgorithmSpecification": {
            "TrainingInputMode": "File",
            "TrainingImage": f"763104351884.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-training:2.0.0-cpu-py310",
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
        tags=_MANAGED_TAGS,
    )
    return {"jobId": resp["jobId"], "jobName": job_name}


def _terminate_quietly(ctx, job_id):
    ctx.client("batch").terminate_service_job(jobId=job_id, reason="sim2real-cleanup")


def _retry_delete(fn, timeout_s=300.0):
    """Run a Batch delete; retry its ClientException refusals every 2 s to timeout_s while a
    dependent finishes deleting. A "does not exist" answer is done; every other error raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                return
            if err["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _wait_jq_gone(batch, name, timeout_s=300.0):
    """Poll every 2 s until DescribeJobQueues lists the queue absent or DELETED."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        queues = batch.describe_job_queues(jobQueues=[name])["jobQueues"]
        if not queues or queues[0]["status"] == "DELETED":
            return
        time.sleep(2)
    raise AssertionError(f"job queue {name} still present {timeout_s:.0f}s after DeleteJobQueue")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
