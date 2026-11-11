"""braket-create-spending-limit-idempotency-under-concurrent-retries."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "braket-create-spending-limit-idempotency-under-concurrent-retries"
GROUP = "concurrency"
SERVICES = ["braket"]

# CreateSpendingLimit is a QPU-only cost control: other regions' QPUs are rejected from us-west-2
# (ValidationException "Device ARN ... is invalid") and its own D-Wave QPU is retired, so a create cannot
# succeed there. A simulator device and a retired QPU each draw their own distinct rejection instead.
SIMULATOR_ARN = "arn:aws:braket:::device/quantum-simulator/amazon/sv1"
RETIRED_QPU_ARN = "arn:aws:braket:us-west-2::device/qpu/d-wave/Advantage_system6"
RACERS = 8


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """8 concurrent CreateSpendingLimit calls sharing one clientToken on SV1 all fail with ValidationException
    "Spending limits can not be created for simulator devices.", 8 on a retired QPU all fail with
    DeviceRetiredException "Device is RETIRED. Try another device.", and neither device has a spending limit."""
    braket = ctx.client("braket")

    sim_token = ctx.unique_name("sim2real-idem-sim-")
    sim_errors = _race_create_spending_limit(braket, SIMULATOR_ARN, sim_token)
    for err in sim_errors:
        assert err["Code"] == "ValidationException", (
            f"simulator device: expected ValidationException, got {err['Code']!r}: {err}"
        )
        assert err["Message"] == "Spending limits can not be created for simulator devices.", (
            f"simulator device: expected the simulator-specific message, got {err['Message']!r}"
        )

    retired_token = ctx.unique_name("sim2real-idem-retired-")
    retired_errors = _race_create_spending_limit(braket, RETIRED_QPU_ARN, retired_token)
    for err in retired_errors:
        assert err["Code"] == "DeviceRetiredException", (
            f"retired device: expected DeviceRetiredException, got {err['Code']!r}: {err}"
        )
        assert err["Message"] == "Device is RETIRED. Try another device.", (
            f"retired device: expected the retirement-specific message, got {err['Message']!r}"
        )

    for device_arn in (SIMULATOR_ARN, RETIRED_QPU_ARN):
        resp = braket.search_spending_limits(
            filters=[{"name": "deviceArn", "values": [device_arn], "operator": "EQUAL"}]
        )
        assert resp.get("spendingLimits") == [], (
            f"a rejected create must never persist a spending limit for {device_arn}, "
            f"got {resp.get('spendingLimits')!r}"
        )


def _race_create_spending_limit(braket, device_arn: str, client_token: str) -> list[dict]:
    """Fire RACERS concurrent CreateSpendingLimit calls sharing one clientToken at
    device_arn and return each call's ClientError.response["Error"] (raises if any
    call unexpectedly succeeds)."""

    def _create():
        try:
            braket.create_spending_limit(
                clientToken=client_token,
                deviceArn=device_arn,
                spendingLimit="7.00",
            )
        except ClientError as exc:
            return exc.response["Error"]
        raise AssertionError(f"create_spending_limit against {device_arn} unexpectedly succeeded")

    with ThreadPoolExecutor(max_workers=RACERS) as pool:
        futures = [pool.submit(_create) for _ in range(RACERS)]
        errors = [fut.result() for fut in as_completed(futures)]

    assert len(errors) == RACERS, f"expected {RACERS} responses, got {len(errors)}"
    return errors


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
