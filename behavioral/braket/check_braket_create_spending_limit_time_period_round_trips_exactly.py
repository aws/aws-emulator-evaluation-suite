"""braket-create-spending-limit-time-period-round-trips-exactly."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "braket-create-spending-limit-time-period-round-trips-exactly"
GROUP = "state"
SERVICES = ["braket"]

# Spending limits are a QPU-only cost control (CreateSpendingLimit rejects simulator devices with
# ValidationException), and a QPU is a physical device resident in one specific region -- us-west-2
# (where this suite otherwise runs) hosts none. The client is pinned to us-east-1, which has a
# resident QPU (IonQ Forte-1), via `ctx.client(..., region=)` rather than a hand-rolled boto3
# client.
QPU_REGION = "us-east-1"
QPU_DEVICE_ARN = "arn:aws:braket:us-east-1::device/qpu/ionq/Forte-1"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A spending limit's explicit timePeriod (start/end epoch seconds) is stored and returned
    unchanged, not silently truncated or shifted by the backend.
    """
    braket = ctx.client("braket", region=QPU_REGION)
    device_arn = QPU_DEVICE_ARN

    start_at = datetime.now(timezone.utc).replace(microsecond=0)
    end_at = start_at + timedelta(days=30)

    arn = braket.create_spending_limit(
        clientToken=ctx.unique_name("sim2real-period-create-"),
        deviceArn=device_arn,
        spendingLimit="1.00",
        timePeriod={"startAt": start_at, "endAt": end_at},
        tags={"sim2real-check": "spending-limit-time-period"},
    )["spendingLimitArn"]
    ctx.on_cleanup(lambda: _best_effort_delete(braket, arn))

    found = _poll_until(
        lambda: _find_spending_limit(braket, device_arn, arn),
        lambda item: item is not None,
        timeout_s=30,
        interval_s=2,
    )
    period = found["timePeriod"]
    assert period["startAt"] == start_at, f"startAt mismatch: {period['startAt']!r} != {start_at!r}"
    assert period["endAt"] == end_at, f"endAt mismatch: {period['endAt']!r} != {end_at!r}"


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
