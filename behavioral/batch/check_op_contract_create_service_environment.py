"""op-contract-createServiceEnvironment."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-createServiceEnvironment"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateServiceEnvironment provisions a VALID/ENABLED SageMaker-training environment
    with the requested capacity limits; a negative maxCapacity is rejected and creates nothing."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-se-")
    resp = batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"maxCapacity": 2, "capacityUnit": "NUM_INSTANCES"}],
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

    assert resp["serviceEnvironmentName"] == name
    assert resp["serviceEnvironmentArn"].endswith(f"/{name}")

    se = _poll_se_status(ctx, name, {"VALID"})
    assert se["serviceEnvironmentType"] == "SAGEMAKER_TRAINING"
    assert se["state"] == "ENABLED"
    assert se["capacityLimits"] == [{"maxCapacity": 2, "capacityUnit": "NUM_INSTANCES"}]

    # Error boundary: a negative maxCapacity is rejected and no resource is created.
    bad_name = ctx.unique_name("sim2real-batch-se-bad-")
    code, message, request_id = _error(
        lambda: batch.create_service_environment(
            serviceEnvironmentName=bad_name,
            serviceEnvironmentType="SAGEMAKER_TRAINING",
            capacityLimits=[{"maxCapacity": -1, "capacityUnit": "NUM_INSTANCES"}],
        )
    )
    assert code == "ClientException", f"expected ClientException, got {code!r}"
    # Batch wraps this validation message with the request id of the refused call.
    expected_message = (
        f"Error executing request, Exception : Max capacity must be more than 0., RequestId: {request_id}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    leftover = batch.describe_service_environments(serviceEnvironments=[bad_name])["serviceEnvironments"]
    assert leftover == [], "invalid create must not leave a service environment behind"


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message, RequestId). An unexpected success
    raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return (
            exc.response["Error"]["Code"],
            exc.response["Error"].get("Message"),
            exc.response.get("ResponseMetadata", {}).get("RequestId"),
        )
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
