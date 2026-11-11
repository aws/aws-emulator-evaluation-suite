"""jq-snapshot-and-list-jobs-status-filter."""

from __future__ import annotations
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "jq-snapshot-and-list-jobs-status-filter"
GROUP = 'job-queue'
SERVICES = ['batch']

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _swallow(fn):
    """Run a teardown call; every error propagates."""
    fn()


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _describe_jq(bat, name):
    qs = bat.describe_job_queues(jobQueues=[name]).get("jobQueues", [])
    return qs[0] if qs else None


def _wait_jq_status(bat, name, statuses, timeout_s=120, interval_s=3):
    return _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is not None and jq.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"job queue {name} status in {sorted(statuses)}",
    )


def _describe_se(bat, name):
    envs = bat.describe_service_environments(serviceEnvironments=[name]).get(
        "serviceEnvironments", []
    )
    return envs[0] if envs else None


def _wait_se_status(bat, name, statuses, timeout_s=120, interval_s=3):
    return _poll_until(
        lambda: _describe_se(bat, name),
        lambda se: se is not None and se.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"service environment {name} status in {sorted(statuses)}",
    )


def _teardown_jq(ctx, bat, name):
    """Disable a job queue, wait for it to settle, delete it and wait for it to be gone; an
    already-gone one is fine."""
    try:
        bat.update_job_queue(jobQueue=name, state="DISABLED")
        _wait_jq_status(bat, name, {"VALID", "INVALID"}, timeout_s=60)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    _retry_delete(lambda: bat.delete_job_queue(jobQueue=name))
    _wait_jq_gone(bat, name)


def _teardown_se(ctx, bat, name):
    """Disable a service environment, wait for it to settle, then delete it.

    A delete attempted while the environment is still transitioning (UPDATING) is rejected;
    without waiting for it to land on DISABLED/VALID first, the delete silently no-ops and
    leaks the environment.
    """
    try:
        bat.update_service_environment(serviceEnvironment=name, state="DISABLED")
        _poll_until(
            lambda: _describe_se(bat, name),
            lambda se: se is not None and se.get("state") == "DISABLED" and se.get("status") == "VALID",
            timeout_s=90,
            interval_s=3,
            description=f"service environment {name} settled to DISABLED/VALID",
        )
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    _retry_delete(lambda: bat.delete_service_environment(serviceEnvironment=name))


def _create_service_environment(ctx, bat, name=None, max_capacity=4, state="ENABLED"):
    name = name or ctx.unique_name("sim2real-behav-se-")
    resp = bat.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        state=state,
        capacityLimits=[{"maxCapacity": max_capacity, "capacityUnit": "NUM_INSTANCES"}],
        tags=dict(_MANAGED_TAGS),
    )
    ctx.on_cleanup(lambda: _teardown_se(ctx, bat, name))
    _wait_se_status(bat, name, {"VALID", "INVALID"})
    return name, resp["serviceEnvironmentArn"]


def _create_service_job_queue(ctx, bat, se_arn, name=None, priority=1, state="ENABLED", scheduling_policy_arn=None):
    name = name or ctx.unique_name("sim2real-behav-sjq-")
    kwargs = dict(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        state=state,
        priority=priority,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": se_arn}],
        tags=dict(_MANAGED_TAGS),
    )
    if scheduling_policy_arn:
        kwargs["schedulingPolicyArn"] = scheduling_policy_arn
    resp = bat.create_job_queue(**kwargs)
    ctx.on_cleanup(lambda: _teardown_jq(ctx, bat, name))
    _wait_jq_status(bat, name, {"VALID", "INVALID"})
    return name, resp["jobQueueArn"]


def _submit_service_job(ctx, bat, jq_name, instance_count=2):
    """Ask for more instances than the environment's capacity, so the job is deterministically
    held at RUNNABLE (blocked on capacity), not racing a real SageMaker training run. The
    role ARN is a fabricated placeholder: the job never leaves RUNNABLE, so it is never assumed.
    No schedulingPriority: real AWS Batch rejects it unless the queue carries a fair-share
    scheduling policy, which this plain queue does not have."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    job_name = ctx.unique_name("sim2real-behav-sj-")
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
    resp = bat.submit_service_job(
        jobName=job_name,
        jobQueue=jq_name,
        serviceJobType="SAGEMAKER_TRAINING",
        serviceRequestPayload=json.dumps(payload),
    )
    job_id = resp["jobId"]
    ctx.on_cleanup(
        lambda: _swallow(lambda: bat.terminate_service_job(jobId=job_id, reason="sim2real-behav cleanup"))
    )
    return job_id, resp["jobArn"]


def _wait_service_job_status(bat, job_id, statuses, timeout_s=120, interval_s=3):
    return _poll_until(
        lambda: bat.describe_service_job(jobId=job_id),
        lambda j: j is not None and j.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"service job {job_id} status in {sorted(statuses)}",
    )


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetJobQueueSnapshot on an empty queue reports an empty front-of-queue; once a service
    job is submitted, the snapshot and ListServiceJobs' jobStatus filter must agree on where it
    is -- and both must stop reporting it once it reaches a terminal state."""
    bat = ctx.client("batch")
    _se_name, se_arn = _create_service_environment(ctx, bat, max_capacity=1, state="ENABLED")
    jq_name, _jq_arn = _create_service_job_queue(ctx, bat, se_arn, priority=1, state="ENABLED")

    empty_snapshot = bat.get_job_queue_snapshot(jobQueue=jq_name)["frontOfQueue"]
    assert empty_snapshot.get("jobs", []) == [], (
        f"an empty queue must report an empty front-of-queue, got {empty_snapshot.get('jobs')}"
    )

    job_id, job_arn = _submit_service_job(ctx, bat, jq_name, instance_count=2)
    described = _wait_service_job_status(bat, job_id, {"RUNNABLE"})
    assert described["status"] == "RUNNABLE", f"expected job stuck RUNNABLE, got {described['status']}"

    snapshot = _poll_until(
        lambda: bat.get_job_queue_snapshot(jobQueue=jq_name),
        lambda s: any(j.get("jobArn") == job_arn for j in s.get("frontOfQueue", {}).get("jobs", [])),
        timeout_s=90,
        description="RUNNABLE service job visible in GetJobQueueSnapshot",
    )
    front_arns = [j["jobArn"] for j in snapshot["frontOfQueue"]["jobs"]]
    assert job_arn in front_arns, f"submitted service job not present at front of queue: {front_arns}"

    # ListServiceJobs' explicit RUNNABLE filter must surface it...
    running_ids = {
        j["jobId"] for j in bat.list_service_jobs(jobQueue=jq_name, jobStatus="RUNNABLE")["jobSummaryList"]
    }
    assert job_id in running_ids, f"expected {job_id} in ListServiceJobs(jobStatus=RUNNABLE), got {running_ids}"

    # ...but a FAILED filter on the same queue, at the same moment, must not.
    failed_ids = {
        j["jobId"] for j in bat.list_service_jobs(jobQueue=jq_name, jobStatus="FAILED")["jobSummaryList"]
    }
    assert job_id not in failed_ids, (
        f"RUNNABLE job {job_id} leaked into ListServiceJobs(jobStatus=FAILED): {failed_ids}"
    )

    # Terminate it, then require both the snapshot and the status filter to converge on "gone".
    bat.terminate_service_job(jobId=job_id, reason="sim2real-behav status-filter teardown")
    final = _wait_service_job_status(bat, job_id, {"FAILED", "SUCCEEDED"})
    assert final["status"] == "FAILED", f"expected a terminated RUNNABLE job to land FAILED, got {final['status']}"

    final_snapshot = _poll_until(
        lambda: bat.get_job_queue_snapshot(jobQueue=jq_name),
        lambda s: not any(j.get("jobArn") == job_arn for j in s.get("frontOfQueue", {}).get("jobs", [])),
        timeout_s=90,
        description="terminated service job absent from GetJobQueueSnapshot",
    )
    final_front_arns = [j["jobArn"] for j in final_snapshot["frontOfQueue"]["jobs"]]
    assert job_arn not in final_front_arns, (
        f"terminated service job still present at front of queue: {final_front_arns}"
    )

    final_running_ids = {
        j["jobId"] for j in bat.list_service_jobs(jobQueue=jq_name, jobStatus="RUNNABLE")["jobSummaryList"]
    }
    assert job_id not in final_running_ids, f"terminated job {job_id} still in RUNNABLE filter: {final_running_ids}"

    final_failed_ids = _poll_until(
        lambda: {j["jobId"] for j in bat.list_service_jobs(jobQueue=jq_name, jobStatus="FAILED")["jobSummaryList"]},
        lambda ids: job_id in ids,
        timeout_s=60,
        description="terminated service job visible in ListServiceJobs(jobStatus=FAILED)",
    )
    assert job_id in final_failed_ids, f"expected {job_id} in ListServiceJobs(jobStatus=FAILED), got {final_failed_ids}"


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
