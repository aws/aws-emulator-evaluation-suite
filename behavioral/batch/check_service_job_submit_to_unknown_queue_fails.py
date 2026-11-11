"""service-job-submit-to-unknown-queue-fails."""

from __future__ import annotations
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "service-job-submit-to-unknown-queue-fails"
GROUP = 'overly-permissive'
SERVICES = ['batch']


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


def _poll_until(probe, predicate, *, timeout_s=120, interval_s=3, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")


def _create_service_environment(ctx, bat):
    name = ctx.unique_name("sim2real-behav-se-")
    arn = bat.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        state="ENABLED",
        capacityLimits=[{"capacityUnit": "NUM_INSTANCES", "maxCapacity": 4}],
    )["serviceEnvironmentArn"]

    def _teardown():
        _swallow(lambda: bat.update_service_environment(serviceEnvironment=arn, state="DISABLED"))
        _swallow(
            lambda: _poll_until(
                lambda: bat.describe_service_environments(serviceEnvironments=[arn])["serviceEnvironments"][0]["status"],
                lambda s: s in ("VALID", "INVALID"),
                timeout_s=90,
                description="service environment settles before delete",
            )
        )
        _swallow(lambda: bat.delete_service_environment(serviceEnvironment=arn))

    ctx.on_cleanup(_teardown)
    _poll_until(
        lambda: bat.describe_service_environments(serviceEnvironments=[arn])["serviceEnvironments"][0]["status"],
        lambda s: s in ("VALID", "INVALID"),
        timeout_s=90,
        description="service environment reaches a terminal validation status",
    )
    return arn


def _create_service_job_queue(ctx, bat, env_arn):
    name = ctx.unique_name("sim2real-behav-sjq-")
    arn = bat.create_job_queue(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        priority=1,
        state="ENABLED",
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": env_arn}],
    )["jobQueueArn"]

    def _teardown():
        _swallow(lambda: bat.update_job_queue(jobQueue=arn, state="DISABLED"))
        _swallow(
            lambda: _poll_until(
                lambda: bat.describe_job_queues(jobQueues=[arn])["jobQueues"][0]["status"],
                lambda s: s in ("VALID", "INVALID"),
                timeout_s=90,
                description="job queue settles before delete",
            )
        )
        _swallow(lambda: bat.delete_job_queue(jobQueue=arn))

    ctx.on_cleanup(_teardown)
    _poll_until(
        lambda: bat.describe_job_queues(jobQueues=[arn])["jobQueues"][0]["status"],
        lambda s: s in ("VALID", "INVALID"),
        timeout_s=90,
        description="job queue reaches a terminal validation status",
    )
    return name


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SubmitServiceJob to a queue that does not exist must be rejected. A positive control --
    the identical call against a real SAGEMAKER_TRAINING queue -- must be accepted first, so the
    rejection cannot be confused with the account having no working SubmitServiceJob path at all.
    """
    bat = ctx.client("batch")
    env_arn = _create_service_environment(ctx, bat)
    real_queue = _create_service_job_queue(ctx, bat, env_arn)

    control_name = ctx.unique_name("sjob-control-")
    control = bat.submit_service_job(
        jobName=control_name,
        jobQueue=real_queue,
        serviceJobType="SAGEMAKER_TRAINING",
        serviceRequestPayload='{"TrainingJobName":"sim2real-behav-batch-control"}',
    )
    control_id = control["jobId"]
    ctx.on_cleanup(
        lambda: _swallow(lambda: bat.terminate_service_job(jobId=control_id, reason="sim2real-cleanup"))
    )

    job_name = ctx.unique_name("sjob-")
    absent_queue = ctx.unique_name("sim2real-behav-batch-absent-queue-")
    error = _error(
        lambda: bat.submit_service_job(
            jobName=job_name,
            jobQueue=absent_queue,
            serviceJobType="SAGEMAKER_TRAINING",
            serviceRequestPayload='{"TrainingJobName":"sim2real-behav-batch-absent"}',
        )
    )
    code = error.get("Code")
    message = error.get("Message", "")
    assert code == "ClientException", (
        f"expected ClientException submitting a service job to a nonexistent job queue, "
        f"got code={code!r} message={message!r}"
    )
    assert message == f"JobQueue {absent_queue} not found.", (
        f"expected the exact queue-not-found message naming {absent_queue!r}, got {message!r}"
    )

    found = bat.list_service_jobs(
        jobQueue=real_queue,
        filters=[{"name": "JOB_NAME", "values": [job_name]}],
    ).get("jobSummaryList", [])
    assert found == [], f"expected no service job to exist for {job_name!r}, found {found!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
