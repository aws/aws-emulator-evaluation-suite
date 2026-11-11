"""service-environment-delete-while-enabled-fails."""

from __future__ import annotations
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "service-environment-delete-while-enabled-fails"
GROUP = 'overly-permissive'
SERVICES = ['batch']

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


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
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _teardown_se(ctx, bat, name))
    _wait_se_status(bat, name, {"VALID", "INVALID"})
    return name, resp["serviceEnvironmentArn"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a service environment that is still ENABLED must fail; disabling it first
    lets the identical delete call succeed, proving the rejection is about state, not delete
    being universally refused."""
    bat = ctx.client("batch")
    name, arn = _create_service_environment(ctx, bat, state="ENABLED")

    code, message = _client_error(lambda: bat.delete_service_environment(serviceEnvironment=name))
    assert code == "ClientException", (
        f"expected ClientException deleting an ENABLED service environment, got {code!r}"
    )
    assert message == "Cannot delete an enabled service environment, set the state to DISABLED first.", (
        f"expected 'Cannot delete an enabled service environment, set the state to DISABLED first.', got {message!r}"
    )

    se = _describe_se(bat, name)
    assert se is not None and se["status"] != "DELETED", "service environment must survive the rejected delete"

    # Positive control: disabling first lets the identical delete call succeed. Without this
    # leg, "rejects delete while ENABLED" is indistinguishable from "rejects delete entirely".
    bat.update_service_environment(serviceEnvironment=name, state="DISABLED")
    _wait_se_status(bat, name, {"VALID", "INVALID"})

    bat.delete_service_environment(serviceEnvironment=name)
    gone = _poll_until(
        lambda: _describe_se(bat, name),
        lambda se: se is None,
        timeout_s=120,
        interval_s=3,
        description=f"service environment {name} deleted after being disabled",
    )
    assert gone is None, "service environment must be gone once the disabled delete succeeds"

    # The now-deleted identifier no longer accepts a mutation either.
    dead_code, dead_message = _client_error(
        lambda: bat.update_service_environment(serviceEnvironment=name, state="ENABLED")
    )
    assert dead_code == "ClientException", (
        f"expected ClientException updating a deleted service environment, got {dead_code!r}"
    )
    assert dead_message == f"{arn} does not exist", (
        f"expected {arn + ' does not exist'!r}, got {dead_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
