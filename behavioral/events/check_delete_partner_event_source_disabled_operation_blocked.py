"""delete-partner-event-source-disabled-operation-blocked."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-partner-event-source-disabled-operation-blocked"
GROUP = "overly-permissive"
SERVICES = ["events"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePartnerEventSource from a non-partner account is a ValidationException naming the
    unregistered partner namespace, not a silent no-op, and has no side effect on event buses.
    """
    events = ctx.client("events")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    partner_segment = ctx.unique_name("sim2real-behav-partner-")
    source_name = f"aws.partner/{partner_segment}/testnamespace/testevent"

    baseline = {
        bus["Name"] for bus in events.list_event_buses(NamePrefix=source_name)["EventBuses"]
    }

    # The namespace check runs before authorization; OperationDisabledException is reachable
    # only for a registered partner namespace, which an ordinary account cannot construct.
    err = _error(
        lambda: events.delete_partner_event_source(Name=source_name, Account=account)
    )
    namespace = source_name.rsplit("/", 2)[0]
    expected = (
        "ValidationException",
        f"Caller is not whitelisted for the event source partner namespace {namespace}",
    )
    assert err == expected, f"expected {expected}, got {err}"

    after = {bus["Name"] for bus in events.list_event_buses(NamePrefix=source_name)["EventBuses"]}
    assert baseline == after, f"expected no change, before={baseline} after={after}"

    # Positive control: the same credentials can manage an ordinary bus.
    bus_name = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus_name)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: events.delete_event_bus(Name=bus_name)))
    described = events.describe_event_bus(Name=bus_name)
    assert described["Name"] == bus_name


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
