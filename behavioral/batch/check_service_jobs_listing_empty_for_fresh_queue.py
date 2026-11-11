"""service-jobs-listing-empty-for-fresh-queue."""

from __future__ import annotations
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "service-jobs-listing-empty-for-fresh-queue"
GROUP = 'service-environment'
SERVICES = ['batch']


def _swallow(fn):
    """Run fn(), swallowing any exception (best-effort teardown step)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


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
    """Disable a job queue, wait for it to settle, then delete it (best-effort)."""
    try:
        bat.update_job_queue(jobQueue=name, state="DISABLED")
        _wait_jq_status(bat, name, {"VALID", "INVALID"}, timeout_s=60)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    _swallow(lambda: bat.delete_job_queue(jobQueue=name))


def _teardown_se(ctx, bat, name):
    """Disable a service environment then delete it (best-effort)."""
    _swallow(lambda: bat.update_service_environment(serviceEnvironment=name, state="DISABLED"))
    _swallow(lambda: bat.delete_service_environment(serviceEnvironment=name))


def _create_service_environment(ctx, bat, name=None, max_capacity=4, state="ENABLED"):
    name = name or ctx.unique_name("sim2real-behav-se-")
    resp = bat.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        state=state,
        capacityLimits=[{"maxCapacity": max_capacity, "capacityUnit": "NUM_INSTANCES"}],
        tags={"sim2real-check": CHECK},
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
    )
    if scheduling_policy_arn:
        kwargs["schedulingPolicyArn"] = scheduling_policy_arn
    kwargs["tags"] = {"sim2real-check": CHECK}
    resp = bat.create_job_queue(**kwargs)
    ctx.on_cleanup(lambda: _teardown_jq(ctx, bat, name))
    _wait_jq_status(bat, name, {"VALID", "INVALID"})
    return name, resp["jobQueueArn"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created service job queue reports no jobs, and filters accept statuses."""
    bat = ctx.client("batch")
    _se_name, se_arn = _create_service_environment(ctx, bat, state="ENABLED")
    jq_name, _jq_arn = _create_service_job_queue(ctx, bat, se_arn, priority=1, state="ENABLED")

    assert bat.list_service_jobs(jobQueue=jq_name).get("jobSummaryList", []) == [], (
        "a fresh queue must not report any service jobs"
    )
    for status in ("SUBMITTED", "RUNNABLE", "RUNNING", "SUCCEEDED", "FAILED"):
        got = bat.list_service_jobs(jobQueue=jq_name, jobStatus=status).get("jobSummaryList", [])
        assert got == [], f"status filter {status} on a fresh queue should be empty, got {got}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
