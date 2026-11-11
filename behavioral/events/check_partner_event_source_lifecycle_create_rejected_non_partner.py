"""partner-event-source-lifecycle-create-rejected-non-partner."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partner-event-source-lifecycle-create-rejected-non-partner"
GROUP = "state-machine"
SERVICES = ["events"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Create, Describe and DeletePartnerEventSource from a non-partner account are all refused with
    the same partner-namespace ValidationException (never ResourceNotFound), while an ordinary
    event bus lifecycle with the same credentials still succeeds.
    """
    events = ctx.client("events")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    partner_segment = ctx.unique_name("sim2real-behav-partner-")
    source_name = f"aws.partner/{partner_segment}/testnamespace/testevent"

    # The namespace check runs before any privilege or existence check, so all three partner
    # operations fail with the same ValidationException.
    refused = ("ValidationException", _not_allowlisted(source_name))
    create_err = _error(
        lambda: events.create_partner_event_source(Name=source_name, Account=account)
    )
    assert create_err == refused, f"expected {refused!r}, got {create_err!r}"

    describe_err = _error(lambda: events.describe_partner_event_source(Name=source_name))
    assert describe_err == refused, (
        f"partner event source must not have been created, expected {refused!r}, "
        f"got {describe_err!r}"
    )

    delete_err = _error(
        lambda: events.delete_partner_event_source(Name=source_name, Account=account)
    )
    assert delete_err == refused, f"expected {refused!r}, got {delete_err!r}"

    # Positive control: the refusal above is targeted, not a blanket deny for these credentials.
    bus_name = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus_name)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: events.delete_event_bus(Name=bus_name)))
    described = events.describe_event_bus(Name=bus_name)
    assert described["Name"] == bus_name


def _not_allowlisted(name: str) -> str:
    """EventBridge's refusal for a caller outside a partner namespace; it names
    aws.partner/<namespace>, the first two segments of the source name or prefix."""
    namespace = "/".join(name.split("/")[:2])
    return f"Caller is not whitelisted for the event source partner namespace {namespace}"


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
