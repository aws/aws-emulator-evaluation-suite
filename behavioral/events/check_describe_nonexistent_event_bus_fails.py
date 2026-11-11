"""describe-nonexistent-event-bus-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-nonexistent-event-bus-fails"
GROUP = 'event-bus'
SERVICES = ['events']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeEventBus on a bus that was never created raises ResourceNotFoundException,
    while a real bus keeps describing fine before and after the failed call."""
    ev = ctx.client("events")
    name = ctx.unique_name("sim2real-behav-bus-")
    resp = ev.create_event_bus(Name=name)
    ctx.on_cleanup(lambda n=name: ev.delete_event_bus(Name=n))

    # positive control: the bus we just created describes successfully
    described = ev.describe_event_bus(Name=name)
    assert described["Name"] == name
    assert described["Arn"] == resp["EventBusArn"]

    bogus = ctx.unique_name("sim2real-behav-nobus-")
    err = _error(lambda: ev.describe_event_bus(Name=bogus))
    assert err == ("ResourceNotFoundException", f"Event bus {bogus} does not exist."), (
        f"expected ResourceNotFoundException, got {err!r}"
    )

    # effect unaffected: the real bus is still describable afterwards
    described_again = ev.describe_event_bus(Name=name)
    assert described_again["Name"] == name


def _error(fn):
    """(code, message) of a call that must fail; a call that succeeds raises AssertionError."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected ClientError, call unexpectedly succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
