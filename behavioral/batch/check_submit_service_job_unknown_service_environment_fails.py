"""submit-service-job-unknown-service-environment-fails."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "submit-service-job-unknown-service-environment-fails"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SubmitServiceJob against a job queue that does not exist fails with ClientException naming
    the missing queue and creates no job, while the identical call against an existing
    SAGEMAKER_TRAINING queue is accepted, so the rejection is specific to the missing queue."""
    batch = ctx.client("batch")
    real_queue, _real_env = _create_sagemaker_queue(ctx)

    # Positive control: the same call shape, pointed at a job queue that exists,
    # must be accepted (a jobId minted) — otherwise "Unauthorized" below would be
    # indistinguishable from SubmitServiceJob being denied outright.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    positive_job_name = ctx.unique_name("sim2real-batch-sj-ok-")
    positive_payload = _training_payload(ctx, account_id, positive_job_name)
    accepted = batch.submit_service_job(
        jobName=positive_job_name,
        jobQueue=real_queue,
        serviceJobType="SAGEMAKER_TRAINING",
        serviceRequestPayload=positive_payload,
    )
    accepted_job_id = accepted.get("jobId")
    assert accepted_job_id, f"expected a jobId submitting to a real job queue, got {accepted!r}"
    ctx.on_cleanup(lambda: _undo(lambda: batch.terminate_service_job(jobId=accepted_job_id, reason="sim2real-cleanup")))

    bogus_queue = ctx.unique_name("sim2real-batch-noqueue-")
    job_name = ctx.unique_name("sim2real-batch-sj-")
    payload = _training_payload(ctx, account_id, job_name)

    code = None
    message = ""
    try:
        batch.submit_service_job(
            jobName=job_name,
            jobQueue=bogus_queue,
            serviceJobType="SAGEMAKER_TRAINING",
            serviceRequestPayload=payload,
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message", "")

    # With a SAGEMAKER_TRAINING job queue present in the account (the positive control's),
    # SubmitServiceJob against a nonexistent job queue is rejected with ClientException naming it.
    assert code == "ClientException", (
        f"expected ClientException submitting to a missing job queue, got code={code!r} message={message!r}"
    )
    assert message == f"JobQueue {bogus_queue} not found.", (
        f"expected the exact queue-not-found message naming {bogus_queue!r}, got {message!r}"
    )

    # Confirm no service job was actually created for job_name: ListServiceJobs requires a
    # concrete, existing jobQueue (real AWS: "Job Queue name is required" — it has no mode
    # that searches "all queues"), so query a real job queue we control with a JOB_NAME
    # filter. Since SubmitServiceJob against the bogus queue never returned a jobId, no such
    # job can exist on any queue, including this freshly-created one.
    found = batch.list_service_jobs(
        jobQueue=real_queue,
        filters=[{"name": "JOB_NAME", "values": [job_name]}],
    )["jobSummaryList"]
    assert found == [], f"expected no service job to exist for {job_name!r}, found {found!r}"


def _training_payload(ctx, account_id: str, training_job_name: str) -> str:
    # A fake RoleArn/ECR image/bucket is fine here: SubmitServiceJob only validates the
    # request's shape synchronously, so this never provisions real SageMaker compute either
    # against the bogus queue (which is rejected before dispatch) or the real one (the
    # positive control terminates the minted job immediately, before it could be scheduled).
    return json.dumps(
        {
            "TrainingJobName": training_job_name,
            "RoleArn": f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-batch-fake-role-')}",
            "AlgorithmSpecification": {
                "TrainingInputMode": "File",
                "TrainingImage": f"123456789012.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-training:2.1.0-cpu-py310",
                "ContainerEntrypoint": ["sleep", "60"],
            },
            "ResourceConfig": {"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 1},
            "OutputDataConfig": {"S3OutputPath": f"s3://sim2real-batch-no-such-bucket-{account_id}/output"},
            "StoppingCondition": {"MaxRuntimeInSeconds": 60},
        }
    )


# ===== helpers =====

def _undo(fn: Callable[[], Any], retry_s: float = 0.0) -> None:
    """Run a teardown step; a resource that does not exist is done. Batch's ClientException for a
    resource still in use is retried every 2 s for retry_s; anything else raises."""
    deadline = time.monotonic() + retry_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            e = err.response["Error"]
            if e["Code"] == "NoSuchEntity" or (
                e["Code"] == "ClientException" and "does not exist" in e.get("Message", "")
            ):
                return
            if e["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 90.0, interval_s: float = 3.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_sagemaker_queue(ctx) -> tuple[str, str]:
    batch = ctx.client("batch")
    env_name = ctx.unique_name("sim2real-svcenv-")
    env_arn = batch.create_service_environment(
        serviceEnvironmentName=env_name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"capacityUnit": "NUM_INSTANCES", "maxCapacity": 4}],
        state="ENABLED",
        tags={"sim2real": "behav"},
    )["serviceEnvironmentArn"]

    def _cleanup_env():
        _undo(lambda: batch.update_service_environment(serviceEnvironment=env_arn, state="DISABLED"))
        _poll_until(
            lambda: batch.describe_service_environments(serviceEnvironments=[env_arn])["serviceEnvironments"][0]["status"],
            lambda s: s in ("VALID", "INVALID"),
            timeout_s=90,
        )
        _undo(lambda: batch.delete_service_environment(serviceEnvironment=env_arn), retry_s=90)

    ctx.on_cleanup(_cleanup_env)
    _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[env_arn])["serviceEnvironments"][0]["status"],
        lambda s: s in ("VALID", "INVALID"),
        timeout_s=90,
    )

    queue_name = ctx.unique_name("sim2real-svcq-")
    queue_arn = batch.create_job_queue(
        jobQueueName=queue_name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        state="ENABLED",
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": env_arn}],
        tags={"sim2real": "behav"},
    )["jobQueueArn"]

    def _cleanup_queue():
        _undo(lambda: batch.update_job_queue(jobQueue=queue_arn, state="DISABLED"))
        _poll_until(
            lambda: batch.describe_job_queues(jobQueues=[queue_arn])["jobQueues"][0]["status"],
            lambda s: s in ("VALID", "INVALID"),
            timeout_s=90,
        )
        _undo(lambda: batch.delete_job_queue(jobQueue=queue_arn), retry_s=90)

    ctx.on_cleanup(_cleanup_queue)
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[queue_arn])["jobQueues"][0]["status"],
        lambda s: s in ("VALID", "INVALID"),
        timeout_s=90,
    )
    return queue_arn, env_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
