"""service-environment-lifecycle."""

from __future__ import annotations
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "service-environment-lifecycle"
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
        tags={"env": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: _teardown_se(ctx, bat, name))
    return name, resp["serviceEnvironmentArn"]


def _client_error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    SUCCESS raises, so an emulator that accepts what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to raise a ClientError, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ServiceEnvironment: CREATING -> VALID, ENABLED<->DISABLED, then DISABLED -> delete -> DELETED."""
    bat = ctx.client("batch")

    def describe():
        return next(
            iter(
                bat.describe_service_environments(serviceEnvironments=[name])
                .get("serviceEnvironments", [])
            ),
            None,
        )

    name, arn = _create_service_environment(ctx, bat, max_capacity=4, state="ENABLED")

    se = _poll_until(describe, lambda se: se is not None and se.get("status") in ("VALID", "INVALID"), timeout_s=120, interval_s=3, description="service environment settled")
    assert se["status"] == "VALID", f"expected VALID, got {se['status']!r}: {se.get('statusReason')}"
    assert se["state"] == "ENABLED", f"expected state ENABLED after create, got {se['state']!r}"
    assert se["serviceEnvironmentArn"] == arn, f"describe arn {se['serviceEnvironmentArn']!r} != create arn {arn!r}"

    bat.update_service_environment(serviceEnvironment=name, state="DISABLED")
    se = _poll_until(describe, lambda se: se is not None and se.get("state") == "DISABLED", timeout_s=120, interval_s=3, description="service environment DISABLED")
    # the DISABLED poll only gates on `state`; `status` is untouched by it, so this is a genuine check
    # that disabling does not also invalidate the environment.
    assert se["status"] == "VALID", f"expected status to remain VALID across ENABLED->DISABLED, got {se['status']!r}"

    bat.delete_service_environment(serviceEnvironment=name)
    _poll_until(describe, lambda se: se is None or se.get("status") == "DELETED", timeout_s=120, interval_s=3, description="service environment deleted")

    # deletes prove gone AND unusable: a mutation on the now-dead id must fail specifically.
    code, message = _client_error(lambda: bat.update_service_environment(serviceEnvironment=name, state="ENABLED"))
    assert code == "ClientException", f"expected ClientException updating a deleted service environment, got {code!r}"
    assert message == f"{arn} does not exist", f"expected {arn + ' does not exist'!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
