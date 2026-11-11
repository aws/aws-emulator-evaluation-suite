"""service-environment-delete-while-attached-to-queue-fails."""

from __future__ import annotations
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "service-environment-delete-while-attached-to-queue-fails"
GROUP = 'overly-permissive'
SERVICES = ['batch']


def _swallow(fn):
    """Run fn(), swallowing any exception (best-effort teardown step)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


def _client_error(fn, *, wait_s=0.0, interval_s=2.0):
    """Call fn() until it raises a ClientError; return (Error.Code, Error.Message). If the call
    still SUCCEEDS once wait_s has elapsed, raise: an emulator that accepts what AWS refuses
    must fail loudly, not read as a code mismatch."""
    deadline = time.monotonic() + wait_s
    while True:
        try:
            result = fn()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")
        time.sleep(interval_s)


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


def _wait_jq_gone(bat, name, timeout_s=120, interval_s=3):
    return _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is None,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"job queue {name} gone",
    )


def _delete_jq(bat, name):
    """Disable then delete a job queue, asserting it is actually gone (not best-effort)."""
    bat.update_job_queue(jobQueue=name, state="DISABLED")
    _wait_jq_status(bat, name, {"VALID", "INVALID"}, timeout_s=90)
    bat.delete_job_queue(jobQueue=name)
    _wait_jq_gone(bat, name, timeout_s=120)


def _wait_se_gone(bat, name, timeout_s=120, interval_s=3):
    return _poll_until(
        lambda: _describe_se(bat, name),
        lambda se: se is None,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"service environment {name} gone",
    )


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
        tags={"sim2real": "true"},
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
    kwargs["tags"] = {"sim2real": "true"}
    resp = bat.create_job_queue(**kwargs)
    ctx.on_cleanup(lambda: _teardown_jq(ctx, bat, name))
    _wait_jq_status(bat, name, {"VALID", "INVALID"})
    return name, resp["jobQueueArn"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A service environment still referenced by a job queue must not be deletable."""
    bat = ctx.client("batch")
    se_name, se_arn = _create_service_environment(ctx, bat, state="ENABLED")
    jq_name, _jq_arn = _create_service_job_queue(ctx, bat, se_arn, priority=1, state="ENABLED")

    # Disable it so that the ENABLED precondition is not what rejects the call.
    bat.update_service_environment(serviceEnvironment=se_name, state="DISABLED")
    _wait_se_status(bat, se_name, {"VALID", "INVALID"})

    code, message = _client_error(lambda: bat.delete_service_environment(serviceEnvironment=se_name))
    assert code == "ClientException", (
        f"expected ClientException deleting a service environment attached to {jq_name}, got {code!r}"
    )
    assert message == "Cannot delete, found existing JobQueue relationship.", (
        f"expected 'Cannot delete, found existing JobQueue relationship.', got {message!r}"
    )

    se = _describe_se(bat, se_name)
    assert se is not None and se["status"] != "DELETED", (
        f"service environment {se_name} must survive the rejected delete, got {se!r}"
    )

    # Restore: remove the job queue attachment entirely, then the identical delete call must succeed.
    _delete_jq(bat, jq_name)

    bat.delete_service_environment(serviceEnvironment=se_name)
    gone = _wait_se_gone(bat, se_name)
    assert gone is None, (
        f"service environment {se_name} still describable after the once-unblocked delete succeeded, got {gone!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
