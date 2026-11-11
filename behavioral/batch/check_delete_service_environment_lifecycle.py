"""delete-service-environment-lifecycle."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-service-environment-lifecycle"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteServiceEnvironment rejects an ENABLED environment, then succeeds once disabled."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-se-")

    batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        state="ENABLED",
        capacityLimits=[{"capacityUnit": "NUM_INSTANCES", "maxCapacity": 1}],
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch-se"},
    )
    ctx.on_cleanup(lambda: _force_delete_se(batch, name))

    env = _poll_until(
        lambda: _describe_se(batch, name),
        lambda e: e is not None and e["status"] in ("VALID", "INVALID"),
        timeout_s=120,
    )
    assert env["status"] == "VALID", f"service environment failed to validate: {env}"
    assert env["state"] == "ENABLED", f"expected state ENABLED right after create, got {env['state']!r}"
    assert env["serviceEnvironmentType"] == "SAGEMAKER_TRAINING", (
        f"expected serviceEnvironmentType SAGEMAKER_TRAINING, got {env['serviceEnvironmentType']!r}"
    )

    # Negative: deleting an ENABLED service environment is rejected.
    code, message = _error_code(lambda: batch.delete_service_environment(serviceEnvironment=name))
    assert code == "ClientException", f"expected ClientException deleting ENABLED SE, got {code}"
    expected = "Cannot delete an enabled service environment, set the state to DISABLED first."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    still_there = _describe_se(batch, name)
    assert still_there is not None and still_there["state"] == "ENABLED" and still_there["status"] == "VALID", (
        f"expected the rejected delete to leave state=ENABLED status=VALID, got {still_there!r}"
    )

    # Positive control: disable it, then the same delete succeeds.
    batch.update_service_environment(serviceEnvironment=name, state="DISABLED")
    disabled = _poll_until(
        lambda: _describe_se(batch, name),
        lambda e: e is not None and e["state"] == "DISABLED" and e["status"] == "VALID",
        timeout_s=120,
    )
    assert disabled["state"] == "DISABLED", f"expected state DISABLED, got {disabled['state']!r}"

    batch.delete_service_environment(serviceEnvironment=name)
    gone = _poll_until(
        lambda: _describe_se(batch, name),
        lambda e: e is None,
        timeout_s=120,
    )
    assert gone is None, "service environment still describable after successful delete"


def _describe_se(batch: Any, name: str) -> dict[str, Any] | None:
    envs = batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"]
    return envs[0] if envs else None


def _poll_until(probe, predicate, timeout_s: float = 120.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _retry_refused(call, *, timeout_s=60):
    """Run a Batch teardown call, where "does not exist" means already gone.

    Batch answers ClientException while a dependency drains: retry that every 2 s, then raise.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                return None
            if err["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _force_delete_se(batch: Any, name: str) -> None:
    envs = batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"]
    if not envs:
        return
    try:
        batch.update_service_environment(serviceEnvironment=name, state="DISABLED")
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    _retry_refused(lambda: batch.delete_service_environment(serviceEnvironment=name), timeout_s=120)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
