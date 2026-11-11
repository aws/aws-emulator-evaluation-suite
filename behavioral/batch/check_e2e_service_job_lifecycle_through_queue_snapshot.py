"""e2e-service-job-lifecycle-through-queue-snapshot."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-service-job-lifecycle-through-queue-snapshot"
GROUP = "e2e"
SERVICES = ["batch"]
SHARE_IDENTIFIER = "sim2realshare"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Submit -> observe in snapshot -> update priority -> terminate -> snapshot/describe agree on terminal state."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    batch = ctx.client("batch")
    se = _create_service_environment(ctx, teardown_deadline, max_capacity=1)
    sp_arn = _create_scheduling_policy(ctx, teardown_deadline)
    jq = _create_job_queue(ctx, se["name"], sp_arn, teardown_deadline)

    # Request more instances than capacity allows so the job is deterministically stuck RUNNABLE
    # (in the queue, not yet dispatched) until we act on it ourselves.
    job = _submit_service_job(ctx, jq["name"], instance_count=2, scheduling_priority=1)
    ctx.on_cleanup(lambda: _terminate_quietly(ctx, job["jobId"]))

    described = _poll_until(
        lambda: batch.describe_service_job(jobId=job["jobId"]),
        lambda d: d["status"] == "RUNNABLE",
        timeout_s=120,
    )
    job_arn = described["jobArn"]
    assert described["schedulingPriority"] == 1, (
        f"expected submitted schedulingPriority 1, got {described['schedulingPriority']}"
    )

    snapshot = _poll_until(
        lambda: batch.get_job_queue_snapshot(jobQueue=jq["name"]),
        lambda s: any(j.get("jobArn") == job_arn for j in s.get("frontOfQueue", {}).get("jobs", [])),
        timeout_s=90,
    )
    front_arns = [j["jobArn"] for j in snapshot["frontOfQueue"]["jobs"]]
    assert job_arn in front_arns, f"expected {job_arn} in frontOfQueue jobs, got {front_arns}"

    # Update priority mid-flight; the job stays RUNNABLE but the new priority is visible.
    batch.update_service_job(jobId=job["jobId"], schedulingPriority=7)
    updated = batch.describe_service_job(jobId=job["jobId"])
    assert updated["schedulingPriority"] == 7, (
        f"expected schedulingPriority 7 after UpdateServiceJob, got {updated['schedulingPriority']}"
    )
    assert updated["status"] == "RUNNABLE", f"expected status RUNNABLE after priority update, got {updated['status']}"

    # Terminate it and confirm both DescribeServiceJob and the snapshot converge on "gone".
    batch.terminate_service_job(jobId=job["jobId"], reason="sim2real-e2e-terminate")
    final = _poll_until(
        lambda: batch.describe_service_job(jobId=job["jobId"]),
        lambda d: d["status"] in {"FAILED", "SUCCEEDED"},
        timeout_s=120,
    )
    assert final["status"] == "FAILED", f"expected terminated job to end FAILED, got {final['status']}"
    assert final["isTerminated"] is True, f"expected isTerminated True on terminal record, got {final['isTerminated']}"
    assert final["schedulingPriority"] == 7, (
        f"expected schedulingPriority 7 to survive to the terminal record, got {final['schedulingPriority']}"
    )  # priority survives to the terminal record

    final_snapshot = _poll_until(
        lambda: batch.get_job_queue_snapshot(jobQueue=jq["name"]),
        lambda s: not any(j.get("jobArn") == job_arn for j in s.get("frontOfQueue", {}).get("jobs", [])),
        timeout_s=90,
    )
    final_arns = [j["jobArn"] for j in final_snapshot["frontOfQueue"]["jobs"]]
    assert job_arn not in final_arns, f"expected {job_arn} gone from frontOfQueue jobs, got {final_arns}"


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
        tags={"sim2real": CHECK},
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
    _delete_when_released(lambda: batch.delete_service_environment(serviceEnvironment=name), teardown_deadline)


def _create_scheduling_policy(ctx, teardown_deadline):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")
    arn = batch.create_scheduling_policy(
        name=name,
        fairsharePolicy={
            "shareDecaySeconds": 0,
            "computeReservation": 0,
            "shareDistribution": [{"shareIdentifier": SHARE_IDENTIFIER, "weightFactor": 1.0}],
        },
        tags={"sim2real": CHECK},
    )["arn"]
    ctx.on_cleanup(lambda: _teardown_scheduling_policy(ctx, arn, teardown_deadline))
    return arn


def _teardown_scheduling_policy(ctx, arn, teardown_deadline):
    # DeleteJobQueue is asynchronous, and the policy is refused while the queue still holds it.
    batch = ctx.client("batch")
    _delete_when_released(lambda: batch.delete_scheduling_policy(arn=arn), teardown_deadline)


def _create_job_queue(ctx, service_environment_name, scheduling_policy_arn, teardown_deadline, priority=1):
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-jq-")
    batch.create_job_queue(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=priority,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": service_environment_name}],
        schedulingPolicyArn=scheduling_policy_arn,
        tags={"sim2real": CHECK},
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
    _delete_when_released(lambda: batch.delete_job_queue(jobQueue=name), teardown_deadline)


def _submit_service_job(ctx, job_queue_name, instance_count=1, scheduling_priority=1):
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
        schedulingPriority=scheduling_priority,
        shareIdentifier=SHARE_IDENTIFIER,
        tags={"sim2real": CHECK},
    )
    return {"jobId": resp["jobId"], "jobName": job_name}


def _terminate_quietly(ctx, job_id):
    ctx.client("batch").terminate_service_job(jobId=job_id, reason="sim2real-cleanup")


# The batch suite's cleanup budget (900 s), one deadline shared by every teardown of a run.
_TEARDOWN_RETRY_S = 900.0


def _delete_when_released(call, teardown_deadline) -> None:
    """Run a Batch delete; while Batch refuses it with "Cannot delete, found existing ..."
    (a dependent still deleting) or "Cannot delete, resource is being modified" (a state update
    still settling), retry every 2 s to the shared deadline; raise everything else."""
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 120.0)
    while True:
        try:
            call()
            return
        except ClientError as exc:
            err = exc.response["Error"]
            in_use = err["Code"] == "ClientException" and err.get("Message", "").startswith(
                ("Cannot delete, found existing", "Cannot delete, resource is being modified")
            )
            if not in_use or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
