"""op-contract-update-service-environment."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-update-service-environment"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateServiceEnvironment applies a capacityLimits change (VALID->UPDATING->VALID)
    and the new maxCapacity is reflected on describe; a negative maxCapacity is rejected
    with ClientException and the currently applied capacity is left unchanged."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-se-")
    created = batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"maxCapacity": 10, "capacityUnit": "NUM_INSTANCES"}],
        state="ENABLED",
        tags={"sim2real": "op-contract-update-service-environment"},
    )
    se_arn = created["serviceEnvironmentArn"]
    ctx.on_cleanup(lambda: _delete_se(ctx, name))

    se0 = _wait_se_status(ctx, name, timeout_s=120)
    assert se0["status"] == "VALID", f"expected status VALID after create, got {se0['status']!r}"
    assert se0["capacityLimits"][0]["maxCapacity"] == 10, (
        f"expected initial maxCapacity 10, got {se0['capacityLimits'][0]['maxCapacity']!r}"
    )

    # success path: raise maxCapacity
    resp = batch.update_service_environment(
        serviceEnvironment=name, capacityLimits=[{"maxCapacity": 20, "capacityUnit": "NUM_INSTANCES"}]
    )
    assert resp["serviceEnvironmentArn"] == se_arn, (
        f"expected update response arn {se_arn!r}, got {resp['serviceEnvironmentArn']!r}"
    )
    assert resp["serviceEnvironmentName"] == name, (
        f"expected update response name {name!r}, got {resp['serviceEnvironmentName']!r}"
    )

    se1 = _wait_se_status(ctx, name, timeout_s=120)
    assert se1["status"] == "VALID", f"expected status VALID after update, got {se1['status']!r}"
    assert se1["capacityLimits"][0]["maxCapacity"] == 20, (
        f"expected maxCapacity 20 after update, got {se1['capacityLimits'][0]['maxCapacity']!r}"
    )

    # error boundary: negative maxCapacity is invalid
    code, message = _error_code(
        lambda: batch.update_service_environment(
            serviceEnvironment=name, capacityLimits=[{"maxCapacity": -5, "capacityUnit": "NUM_INSTANCES"}]
        )
    )
    assert code == "ClientException", f"expected ClientException for negative maxCapacity, got {code!r}"
    assert message == "Max capacity must be more than 0.", f"unexpected message {message!r}"

    # the failed update did not change the applied capacity
    se2 = batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"][0]
    assert se2["capacityLimits"][0]["maxCapacity"] == 20, (
        f"expected maxCapacity to remain 20 after rejected update, got {se2['capacityLimits'][0]['maxCapacity']!r}"
    )


def _error_code(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_se_status(ctx, name: str, timeout_s: float = 120.0) -> dict[str, Any]:
    batch = ctx.client("batch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        ses = batch.describe_service_environments(serviceEnvironments=[name])["serviceEnvironments"]
        if ses and ses[0]["status"] in ("VALID", "INVALID"):
            return ses[0]
        time.sleep(3)
    raise AssertionError(f"service environment {name} did not reach a terminal status within {timeout_s}s")


def _delete_se(ctx, name: str) -> None:
    batch = ctx.client("batch")
    try:
        batch.update_service_environment(serviceEnvironment=name, state="DISABLED")
        _wait_se_status(ctx, name, timeout_s=120)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    batch.delete_service_environment(serviceEnvironment=name)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
