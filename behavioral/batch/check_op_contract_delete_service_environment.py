"""op-contract-deleteServiceEnvironment."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-deleteServiceEnvironment"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteServiceEnvironment removes a DISABLED service environment, but is rejected
    while it's still ENABLED (positive control shows the same delete succeeds once disabled)."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-se-")
    batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"maxCapacity": 1, "capacityUnit": "NUM_INSTANCES"}],
        state="ENABLED",
        tags={"sim2real": "true"},
    )

    def _cleanup():
        try:
            batch.update_service_environment(serviceEnvironment=name, state="DISABLED")
            _poll_se_status(ctx, name, {"VALID", "INVALID"})
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
        batch.delete_service_environment(serviceEnvironment=name)

    ctx.on_cleanup(_cleanup)
    _poll_se_status(ctx, name, {"VALID"})

    # Negative: an ENABLED service environment cannot be deleted.
    code, message = _client_error(lambda: batch.delete_service_environment(serviceEnvironment=name))
    assert code == "ClientException", f"expected ClientException, got {code!r}"
    expected = "Cannot delete an enabled service environment, set the state to DISABLED first."
    assert message == expected, f"expected {expected!r}, got {message!r}"
    still_there = batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"]
    assert len(still_there) == 1 and still_there[0]["state"] == "ENABLED", "must not have been deleted"

    # Positive control: disabling first lets the identical delete call succeed.
    batch.update_service_environment(serviceEnvironment=name, state="DISABLED")
    _poll_se_status(ctx, name, {"VALID", "INVALID"})
    batch.delete_service_environment(serviceEnvironment=name)
    deleted = _poll_until(
        lambda: batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"],
        lambda ses: len(ses) == 0,
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert deleted == [], f"service environment must be fully deleted, still describes as {deleted!r}"


def _client_error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last state={last!r}")


def _poll_se_status(ctx, name, target_statuses, timeout_s=90.0):
    batch = ctx.client("batch")

    def probe():
        r = batch.describe_service_environments(serviceEnvironments=[name])
        ses = r["serviceEnvironments"]
        return ses[0] if ses else None

    return _poll_until(
        probe, lambda se: se is not None and se["status"] in target_statuses, timeout_s=timeout_s, interval_s=2.0
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
