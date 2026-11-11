"""concurrent-service-job-terminate-and-update-race-consistent."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-service-job-terminate-and-update-race-consistent"
GROUP = "concurrency"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch"}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent TerminateServiceJob and UpdateServiceJob on one service job leave it terminal, and
    its schedulingPriority reflects the update's outcome: the new value if accepted, the original
    if rejected."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    batch = ctx.client("batch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    se_arn = _create_service_environment(ctx, teardown_deadline)
    policy_arn = _create_fairshare_scheduling_policy(ctx, teardown_deadline)
    jq_arn = _create_service_job_queue(ctx, se_arn, policy_arn, teardown_deadline)

    job_name = ctx.unique_name("sim2real-batch-sj-")
    submit_priority = 1
    job_id = _submit_stuck_service_job(
        batch, jq_arn, job_name, account_id=account_id, scheduling_priority=submit_priority
    )
    ctx.on_cleanup(lambda: _best_effort_terminate(ctx, job_id))

    # Wait until the job is actually queued (never reaches STARTING/RUNNING against the
    # real SageMaker Training API since it always requests more instances than the
    # 1-instance environment can ever grant) so the race below is against a stable,
    # non-terminal, zero-cost job.
    _poll_until(
        lambda: batch.describe_service_job(jobId=job_id),
        lambda d: d["status"] in ("PENDING", "RUNNABLE", "SCHEDULED"),
        timeout_s=90,
    )

    # Positive control: a solo UpdateServiceJob against this same live, non-terminal job
    # must succeed and persist *before* we ever race it against a terminate. Without this,
    # a target that unconditionally rejects UpdateServiceJob would pass the race assertions
    # below via the "rejected" branch every time, indistinguishable from one that correctly
    # rejects only the race-lost case.
    warmup_priority = 50
    batch.update_service_job(jobId=job_id, schedulingPriority=warmup_priority)
    warmed = _poll_until(
        lambda: batch.describe_service_job(jobId=job_id),
        lambda d: d["schedulingPriority"] == warmup_priority,
        timeout_s=30,
    )
    assert warmed["schedulingPriority"] == warmup_priority, (
        "positive control: UpdateServiceJob on a live, non-terminal job must succeed and persist"
    )
    assert warmed["status"] in ("PENDING", "RUNNABLE", "SCHEDULED"), (
        f"positive control update must not itself move the job out of queued state, got {warmed['status']!r}"
    )
    original_priority = warmup_priority  # the baseline the race below must not disturb on a rejected update

    new_priority = 99
    terminate_outcome: dict = {}
    update_outcome: dict = {}

    # Either racer may legitimately succeed, so each records its outcome inline: None when
    # the call succeeded, else its error code.
    def _terminate():
        try:
            batch.terminate_service_job(jobId=job_id, reason="sim2real-race-terminate")
            terminate_outcome["error"] = None
        except ClientError as err:
            terminate_outcome["error"] = err.response["Error"]["Code"]

    def _update():
        try:
            batch.update_service_job(jobId=job_id, schedulingPriority=new_priority)
            update_outcome["error"] = None
        except ClientError as err:
            update_outcome["error"] = err.response["Error"]["Code"]
            update_outcome["message"] = err.response["Error"].get("Message")

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_terminate), pool.submit(_update)]
        for future in futures:
            future.result()

    # TerminateServiceJob has no documented terminal-state restriction -- it must
    # succeed regardless of how the race resolves.
    assert terminate_outcome["error"] is None, (
        f"TerminateServiceJob unexpectedly failed: {terminate_outcome['error']}"
    )

    final = _poll_service_job_terminal(ctx, job_id)
    assert final["isTerminated"] is True
    assert final["status"] == "FAILED", f"expected terminal status FAILED, got {final['status']!r} (full={final})"


    if update_outcome["error"] is None:
        assert final["schedulingPriority"] == new_priority, (
            "UpdateServiceJob was accepted but its effect was lost after termination"
        )
    else:
        assert update_outcome["error"] == "ClientException", (
            f"expected ClientException for a race-lost update, got {update_outcome['error']}"
        )
        assert final["schedulingPriority"] == original_priority, (
            "UpdateServiceJob was rejected but its effect was silently applied anyway"
        )

    # Overly-permissive check: the job is now confirmed terminal (isTerminated is
    # True, asserted above). A further UpdateServiceJob against a terminal job must
    # be rejected -- an emulator that silently accepts updates on terminal jobs is
    # overly permissive.
    post_terminal_error, message, request_id = _invoke_capturing_error(
        lambda: batch.update_service_job(jobId=job_id, schedulingPriority=42)
    )
    assert post_terminal_error == "ClientException", (
        f"expected ClientException updating an already-terminal service job, got {post_terminal_error}"
    )
    expected_message = "UpdateServiceJob cannot be called on a service job which is completed."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _invoke_capturing_error(fn):
    """Call fn(); return its botocore Error (code, message, request id). An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal
    available and must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response["ResponseMetadata"].get("RequestId"),
        )
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _submit_stuck_service_job(batch, jq_arn, job_name, account_id, scheduling_priority) -> str:
    """Submit a service job that requests more instances than the environment can ever
    grant. This guarantees the job stays queued (never reaches STARTING/RUNNING against
    the real SageMaker Training API) so the check never incurs real training-job compute
    cost and the race below always lands on a stable, non-terminal job."""
    payload = json.dumps(
        {
            "TrainingJobName": job_name,
            "RoleArn": f"arn:aws:iam::{account_id}:role/sim2real-nonexistent-execution-role",
            "AlgorithmSpecification": {
                "TrainingInputMode": "File",
                "TrainingImage": "763104351884.dkr.ecr.us-west-2.amazonaws.com/pytorch-training:2.0.0-cpu-py310",
                "ContainerEntrypoint": ["echo", "hello"],
            },
            "ResourceConfig": {"InstanceType": "ml.c5.xlarge", "InstanceCount": 5, "VolumeSizeInGB": 1},
            "OutputDataConfig": {"S3OutputPath": "s3://sim2real-batch-nonexistent-bucket/output"},
            "StoppingCondition": {"MaxRuntimeInSeconds": 30},
        }
    )
    resp = batch.submit_service_job(
        jobName=job_name,
        jobQueue=jq_arn,
        serviceJobType="SAGEMAKER_TRAINING",
        schedulingPriority=scheduling_priority,
        shareIdentifier="sim2realshare",
        serviceRequestPayload=payload,
        tags=_MANAGED_TAGS,
    )
    return resp["jobId"]


def _create_service_environment(ctx, teardown_deadline) -> str:
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-se-")
    arn = batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"maxCapacity": 1, "capacityUnit": "NUM_INSTANCES"}],
        state="ENABLED",
        tags=_MANAGED_TAGS,
    )["serviceEnvironmentArn"]
    _poll_service_environment_status(ctx, arn, {"VALID"})
    ctx.on_cleanup(lambda: _disable_and_delete_service_environment(ctx, arn, teardown_deadline))
    return arn


def _create_fairshare_scheduling_policy(ctx, teardown_deadline) -> str:
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-fssp-")
    arn = batch.create_scheduling_policy(
        name=name,
        fairsharePolicy={
            "shareDecaySeconds": 0,
            "computeReservation": 0,
            "shareDistribution": [{"shareIdentifier": "sim2realshare", "weightFactor": 1.0}],
        },
        tags=_MANAGED_TAGS,
    )["arn"]
    ctx.on_cleanup(lambda: _delete_when_released(lambda: batch.delete_scheduling_policy(arn=arn), teardown_deadline))
    return arn


def _create_service_job_queue(ctx, se_arn: str, policy_arn: str, teardown_deadline) -> str:
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sjq-")
    arn = batch.create_job_queue(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        state="ENABLED",
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": se_arn}],
        schedulingPolicyArn=policy_arn,
        tags=_MANAGED_TAGS,
    )["jobQueueArn"]
    _poll_job_queue_status(ctx, arn, {"VALID"})
    ctx.on_cleanup(lambda: _disable_and_delete_job_queue(ctx, arn, teardown_deadline))
    return arn


def _poll_service_environment_status(ctx, arn: str, ok_statuses, timeout_s: float = 180.0, interval_s: float = 3.0):
    batch = ctx.client("batch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = batch.describe_service_environments(serviceEnvironments=[arn])
        envs = resp.get("serviceEnvironments", [])
        if envs:
            last = envs[0]
            if last["status"] in ok_statuses:
                return last
            if last["status"] == "INVALID":
                raise AssertionError(f"service environment went INVALID: {last}")
        time.sleep(interval_s)
    raise AssertionError(f"service environment never reached {ok_statuses}, last={last}")


def _poll_job_queue_status(ctx, arn: str, ok_statuses, timeout_s: float = 180.0, interval_s: float = 3.0):
    batch = ctx.client("batch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = batch.describe_job_queues(jobQueues=[arn])
        queues = resp.get("jobQueues", [])
        if queues:
            last = queues[0]
            if last["status"] in ok_statuses:
                return last
            if last["status"] == "INVALID":
                raise AssertionError(f"job queue went INVALID: {last}")
        time.sleep(interval_s)
    raise AssertionError(f"job queue never reached {ok_statuses}, last={last}")


def _poll_service_job_terminal(ctx, job_id: str, timeout_s: float = 240.0, interval_s: float = 3.0):
    batch = ctx.client("batch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = batch.describe_service_job(jobId=job_id)
        if last.get("status") in ("SUCCEEDED", "FAILED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"service job {job_id} never reached a terminal status, last={last}")


def _best_effort_terminate(ctx, job_id: str) -> None:
    batch = ctx.client("batch")
    batch.terminate_service_job(jobId=job_id, reason="sim2real-cleanup")


def _disable_and_delete_job_queue(ctx, arn: str, teardown_deadline) -> None:
    batch = ctx.client("batch")
    batch.update_job_queue(jobQueue=arn, state="DISABLED")
    _poll_job_queue_status(ctx, arn, {"VALID"})
    _delete_when_released(lambda: batch.delete_job_queue(jobQueue=arn), teardown_deadline)
    # DeleteJobQueue is asynchronous; the service environment and scheduling policy deletes
    # that run next are refused while the queue still references them.
    deadline = time.monotonic() + 180
    while batch.describe_job_queues(jobQueues=[arn])["jobQueues"]:
        if time.monotonic() > deadline:
            raise AssertionError(f"job queue {arn} still present 180s after its delete")
        time.sleep(5)


def _disable_and_delete_service_environment(ctx, arn: str, teardown_deadline) -> None:
    batch = ctx.client("batch")
    batch.update_service_environment(serviceEnvironment=arn, state="DISABLED")
    _poll_service_environment_status(ctx, arn, {"VALID"})
    _delete_when_released(lambda: batch.delete_service_environment(serviceEnvironment=arn), teardown_deadline)


# The batch suite's cleanup budget (900 s), one deadline shared by every teardown of a run.
_TEARDOWN_RETRY_S = 900.0


def _delete_when_released(call, teardown_deadline) -> None:
    """Run a Batch delete; while Batch refuses it with "Cannot delete, found existing ..."
    (a dependent still deleting), retry every 2 s to the shared deadline; raise everything else."""
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 120.0)
    while True:
        try:
            call()
            return
        except ClientError as exc:
            err = exc.response["Error"]
            in_use = err["Code"] == "ClientException" and err.get("Message", "").startswith(
                "Cannot delete, found existing"
            )
            if not in_use or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
