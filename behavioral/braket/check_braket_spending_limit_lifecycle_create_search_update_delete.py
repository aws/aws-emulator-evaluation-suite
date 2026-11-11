"""braket-spending-limit-lifecycle-create-search-update-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "braket-spending-limit-lifecycle-create-search-update-delete"
GROUP = "state"
SERVICES = ["braket"]

# Spending limits are a QPU-only cost control (CreateSpendingLimit rejects simulator
# devices with ValidationException), and a QPU is resident in only one region each --
# never in us-west-2, which is where every other check in this suite runs via ctx.region.
# So this check pins its own client to a QPU-resident region rather than following
# ctx.region, the same way ACM/CloudFront checks pin to us-east-1.
QPU_REGION = "us-east-1"
QPU_ARN = "arn:aws:braket:us-east-1::device/qpu/ionq/Forte-1"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A spending limit's full life cycle: create -> visible in search -> update -> deleted."""
    braket = ctx.client("braket", region=QPU_REGION)
    device_arn = QPU_ARN

    arn = braket.create_spending_limit(
        clientToken=ctx.unique_name("sim2real-spend-create-"),
        deviceArn=device_arn,
        spendingLimit="5.00",
        tags={"sim2real:managed": "true"},
    )["spendingLimitArn"]
    deleted = False
    try:
        found = _poll_until(
            lambda: _find_spending_limit(braket, device_arn, arn),
            lambda item: item is not None,
            timeout_s=30,
            interval_s=2,
        )
        assert float(found["spendingLimit"]) == 5.00, (
            f"expected spendingLimit 5.00 right after create, got {found['spendingLimit']!r}"
        )
        assert found["deviceArn"] == device_arn, (
            f"expected deviceArn {device_arn!r} in search result, got {found['deviceArn']!r}"
        )

        braket.update_spending_limit(
            spendingLimitArn=arn,
            clientToken=ctx.unique_name("sim2real-spend-update-"),
            spendingLimit="15.00",
        )
        updated = _poll_until(
            lambda: _find_spending_limit(braket, device_arn, arn),
            lambda item: item is not None and float(item["spendingLimit"]) == 15.00,
            timeout_s=30,
            interval_s=2,
        )
        assert float(updated["spendingLimit"]) == 15.00, (
            f"expected spendingLimit 15.00 after update, got {updated['spendingLimit']!r}"
        )

        braket.delete_spending_limit(spendingLimitArn=arn)
        deleted = True
        _poll_until(
            lambda: _find_spending_limit(braket, device_arn, arn),
            lambda item: item is None,
            timeout_s=30,
            interval_s=2,
        )
        # ListTagsForResource uses its own NotFoundException shape rather than the
        # ResourceNotFoundException used by other read/mutate operations.
        err = _client_error(lambda: braket.list_tags_for_resource(resourceArn=arn))
        assert err["Code"] == "NotFoundException", (
            f"expected NotFoundException reading the deleted spending limit, got {err!r}"
        )
        assert err["Message"] == "Resource was not found", (
            f"expected message 'Resource was not found', got {err['Message']!r}"
        )

        mutate_err = _client_error(
            lambda: braket.update_spending_limit(
                spendingLimitArn=arn,
                clientToken=ctx.unique_name("sim2real-spend-post-delete-"),
                spendingLimit="1.00",
            )
        )
        assert mutate_err["Code"] == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException updating the deleted spending limit, got {mutate_err!r}"
        )
        expected = f"Spending limit {arn} not found"
        assert mutate_err["Message"] == expected, (
            f"expected message {expected!r}, got {mutate_err['Message']!r}"
        )
    finally:
        if not deleted:
            ctx.on_cleanup(lambda: _best_effort_delete(braket, arn))


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
