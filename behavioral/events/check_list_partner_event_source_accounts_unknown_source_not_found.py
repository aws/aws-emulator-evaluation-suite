"""list-partner-event-source-accounts-unknown-source-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-partner-event-source-accounts-unknown-source-not-found"
GROUP = "error-semantics"
SERVICES = ["events"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListPartnerEventSourceAccounts for an unregistered partner namespace fails with
    ValidationException (namespace check precedes the not-found check), stably across names, leaving
    an ordinary bus intact.
    """
    events = ctx.client("events")

    # A real, ordinary resource that the rejected calls must have zero effect on.
    bus_name = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus_name)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: events.delete_event_bus(Name=bus_name)))
    before = {bus["Name"] for bus in events.list_event_buses(NamePrefix=bus_name)["EventBuses"]}
    assert bus_name in before, f"expected {bus_name} in {before}"

    bogus = _partner_source_name(ctx)
    code, message = _error(lambda: events.list_partner_event_source_accounts(EventSourceName=bogus))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == _not_allowlisted(bogus), f"unexpected message {message!r}"

    # A second distinct name shows the namespace rejection is stable.
    other_bogus = _partner_source_name(ctx)
    code, message = _error(
        lambda: events.list_partner_event_source_accounts(EventSourceName=other_bogus)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == _not_allowlisted(other_bogus), f"unexpected message {message!r}"

    # The rejected calls must leave the ordinary bus untouched.
    after = {bus["Name"] for bus in events.list_event_buses(NamePrefix=bus_name)["EventBuses"]}
    assert before == after, f"expected no change, before={before} after={after}"

    # Positive control: an ordinary listing with the same credentials still sees the bus.
    assert bus_name in after, f"expected {bus_name} in {after}"


def _not_allowlisted(name: str) -> str:
    """EventBridge's refusal for a caller outside a partner namespace; it names
    aws.partner/<namespace>, the first two segments of the source name or prefix."""
    namespace = "/".join(name.split("/")[:2])
    return f"Caller is not whitelisted for the event source partner namespace {namespace}"



def _partner_source_name(ctx) -> str:
    """Build a name matching ^aws\\.partner(/[.\\-_A-Za-z0-9]+){2,}$ -- the pattern EventBridge
    requires for partner event source names."""
    suffix = ctx.unique_name("src-").strip("-")
    return f"aws.partner/sim2real.test/{suffix}"


def _error(fn):
    """(code, message) of a call that must fail; a call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


