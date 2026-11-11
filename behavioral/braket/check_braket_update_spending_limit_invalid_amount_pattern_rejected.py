"""braket-update-spending-limit-invalid-amount-pattern-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "braket-update-spending-limit-invalid-amount-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["braket"]

# Spending limits are a QPU-only cost control (CreateSpendingLimit rejects simulator
# devices with ValidationException). No Braket QPU is resident in us-west-2 (the region every
# behavioral check otherwise runs in), so this client is pinned to us-east-1 the way ACM/
# CloudFront checks pin to their control-plane region, and the resident QPU is discovered live
# via SearchDevices rather than hardcoded, since the provider's device catalog (chip models,
# retirements) changes independently of this check.
QPU_REGION = "us-east-1"


def _resident_qpu_arn(braket) -> str:
    # SearchDevices only supports filtering by "deviceArn"; any other filter name is itself rejected
    # with ValidationException, so the QPU/ONLINE narrowing happens client-side.
    resp = braket.search_devices(filters=[])
    for device in resp.get("devices", []):
        if device["deviceType"] == "QPU" and device["deviceStatus"] == "ONLINE":
            return device["deviceArn"]
    raise AssertionError(f"no ONLINE QPU device found in {QPU_REGION}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSpendingLimit rejects a non-numeric amount and leaves the stored value untouched;
    the same call with a well-formed amount (positive control) still succeeds.
    """
    braket = ctx.client("braket", region=QPU_REGION)
    device_arn = _resident_qpu_arn(braket)

    arn = braket.create_spending_limit(
        clientToken=ctx.unique_name("sim2real-badamt-create-"),
        deviceArn=device_arn,
        spendingLimit="5",
        tags={"sim2real-check": CHECK},
    )["spendingLimitArn"]
    ctx.on_cleanup(lambda: _best_effort_delete(braket, arn))

    err = _client_error(
        lambda: braket.update_spending_limit(
            spendingLimitArn=arn,
            clientToken=ctx.unique_name("sim2real-badamt-update-"),
            spendingLimit="not-a-number",
        )
    )
    # Real AWS rejects a malformed spendingLimit at the request-body level with BadRequestException,
    # not ValidationException.
    assert err["Code"] == "BadRequestException", f"expected BadRequestException, got {err!r}"
    assert err["Message"] == "Invalid request body", (
        f"expected message 'Invalid request body', got {err['Message']!r}"
    )

    # Effect absent: the value on record is unchanged by the rejected update.
    unchanged = _poll_until(
        lambda: _find_spending_limit(braket, device_arn, arn),
        lambda item: item is not None,
        timeout_s=30,
        interval_s=2,
    )
    assert unchanged["spendingLimit"] == "5", (
        f"expected the rejected update to leave spendingLimit at '5', got {unchanged['spendingLimit']!r}"
    )

    # Positive control: same operation, a valid amount, succeeds and persists.
    braket.update_spending_limit(
        spendingLimitArn=arn,
        clientToken=ctx.unique_name("sim2real-badamt-goodupdate-"),
        spendingLimit="9.99",
    )
    updated = _poll_until(
        lambda: _find_spending_limit(braket, device_arn, arn),
        lambda item: item is not None and item["spendingLimit"] == "9.99",
        timeout_s=30,
        interval_s=2,
    )
    assert updated["spendingLimit"] == "9.99", (
        f"expected the positive-control update to persist '9.99', got {updated['spendingLimit']!r}"
    )


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _find_spending_limit(braket, device_arn, target_arn):
    resp = braket.search_spending_limits(
        filters=[{"name": "deviceArn", "values": [device_arn], "operator": "EQUAL"}]
    )
    for item in resp.get("spendingLimits", []):
        if item["spendingLimitArn"] == target_arn:
            return item
    return None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _best_effort_delete(braket, arn) -> None:
    try:
        braket.delete_spending_limit(spendingLimitArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
