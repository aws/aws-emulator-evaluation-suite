"""listener-port-range-limit-survives-update."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "listener-port-range-limit-survives-update"
GROUP = "negative"
SERVICES = ["globalaccelerator"]


def _error(fn):
    """Return the (code, message) fn() raised; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _delete_accelerator(ga, arn, budget_s=600.0, delay_s=10.0):
    """Delete ``arn``, retrying while a just-mutated accelerator is still settling."""

    def run_undo() -> None:
        deadline = time.monotonic() + budget_s
        while True:
            try:
                ga.delete_accelerator(AcceleratorArn=arn)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "AcceleratorNotFoundException":
                    return
                if code not in ("AcceleratorNotDisabledException", "TransactionInProgressException"):
                    raise
                if time.monotonic() > deadline:
                    raise
                time.sleep(delay_s)

    return run_undo


def _port_ranges(count: int, base: int = 1000) -> list:
    return [{"FromPort": base + i, "ToPort": base + i} for i in range(count)]


def _listener_arns(ga, accelerator_arn):
    arns, token = [], None
    while True:
        page = ga.list_listeners(
            AcceleratorArn=accelerator_arn, **({"NextToken": token} if token else {})
        )
        arns += [listener["ListenerArn"] for listener in page["Listeners"]]
        token = page.get("NextToken")
        if not token:
            break
    return arns


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateListener accepts exactly ten single-port ranges in order; an eleventh is refused with
    LimitExceededException and its exact message, leaving ListListeners and the listener's ranges
    unchanged, and UpdateListener raising the same listener to eleven is refused the same way.
    """
    ga = ctx.client("globalaccelerator")

    accelerator = ga.create_accelerator(
        Name=ctx.unique_name("sim2real-behav-ga-"),
        IpAddressType="IPV4",
        Enabled=False,
        IdempotencyToken=str(uuid.uuid4()),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Accelerator"]
    accelerator_arn = accelerator["AcceleratorArn"]
    ctx.on_cleanup(_delete_accelerator(ga, accelerator_arn))

    ten_ranges = _port_ranges(10)
    listener = ga.create_listener(
        AcceleratorArn=accelerator_arn,
        Protocol="TCP",
        PortRanges=ten_ranges,
        IdempotencyToken=str(uuid.uuid4()),
    )["Listener"]
    listener_arn = listener["ListenerArn"]
    ctx.on_cleanup(_teardown(lambda: ga.delete_listener(ListenerArn=listener_arn), "ListenerNotFoundException"))

    assert listener["PortRanges"] == ten_ranges, (
        f"CreateListener with 10 port ranges returned {listener['PortRanges']!r}, expected the "
        f"10 ranges in order {ten_ranges!r}"
    )

    described = ga.describe_listener(ListenerArn=listener_arn)["Listener"]
    assert described["PortRanges"] == ten_ranges, (
        f"DescribeListener returned {described['PortRanges']!r}, expected the 10 ranges in order "
        f"{ten_ranges!r}"
    )

    eleven_ranges = _port_ranges(11)
    create_expected_message = (
        "Limit Exceeded for the number of Port Ranges allowed in a Listener for Accelerator "
        f"{accelerator_arn}."
    )

    create_code, create_message = _error(
        lambda: ga.create_listener(
            AcceleratorArn=accelerator_arn,
            Protocol="TCP",
            PortRanges=eleven_ranges,
            IdempotencyToken=str(uuid.uuid4()),
        )
    )
    assert create_code == "LimitExceededException", (
        f"CreateListener with 11 port ranges returned {create_code!r}, expected "
        f"'LimitExceededException'"
    )
    assert create_message == create_expected_message, (
        f"CreateListener with 11 port ranges returned message {create_message!r}, expected "
        f"{create_expected_message!r}"
    )

    remaining_listeners = _listener_arns(ga, accelerator_arn)
    assert remaining_listeners == [listener_arn], (
        f"ListListeners returned {remaining_listeners!r} after the refused 11-range CreateListener, "
        f"expected only the 10-range listener {[listener_arn]!r}"
    )

    update_expected_message = (
        "Limit Exceeded for the number of Port Ranges allowed in a Listener for "
        f"{listener_arn}."
    )
    update_code, update_message = _error(
        lambda: ga.update_listener(ListenerArn=listener_arn, PortRanges=eleven_ranges)
    )
    assert update_code == "LimitExceededException", (
        f"UpdateListener raising the listener to 11 port ranges returned {update_code!r}, expected "
        f"'LimitExceededException'"
    )
    assert update_message == update_expected_message, (
        f"UpdateListener raising the listener to 11 port ranges returned message {update_message!r}, "
        f"expected {update_expected_message!r}"
    )

    after_update = ga.describe_listener(ListenerArn=listener_arn)["Listener"]
    assert after_update["PortRanges"] == ten_ranges, (
        f"the refused UpdateListener changed the ranges anyway: DescribeListener now returns "
        f"{after_update['PortRanges']!r}, expected the original 10 ranges in order {ten_ranges!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
