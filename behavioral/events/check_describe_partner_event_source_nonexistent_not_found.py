"""describe-partner-event-source-nonexistent-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-partner-event-source-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["events"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribePartnerEventSource on a nonexistent name in an unregistered partner namespace is a
    ValidationException naming the namespace, not ResourceNotFoundException: the namespace
    allowlist is checked before existence. The exact message rules out a malformed-name error.
    """
    events = ctx.client("events")

    bogus = _partner_source_name(ctx)
    code, message = _error_code_and_message(
        lambda: events.describe_partner_event_source(Name=bogus)
    )
    assert (code, message) == ("ValidationException", _not_allowlisted(bogus)), repr((code, message))

    other_bogus = _partner_source_name(ctx)
    other_code, other_message = _error_code_and_message(
        lambda: events.describe_partner_event_source(Name=other_bogus)
    )
    assert (other_code, other_message) == ("ValidationException", _not_allowlisted(other_bogus)), (
        repr((other_code, other_message))
    )

    # Positive control: the same credentials can manage an ordinary bus.
    bus_name = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus_name)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: events.delete_event_bus(Name=bus_name)))
    described = events.describe_event_bus(Name=bus_name)
    assert described["Name"] == bus_name, repr(described)


def _not_allowlisted(name: str) -> str:
    """EventBridge's refusal for a caller outside a partner namespace; it names
    aws.partner/<namespace>, the first two segments of the source name or prefix."""
    namespace = "/".join(name.split("/")[:2])
    return f"Caller is not whitelisted for the event source partner namespace {namespace}"



def _partner_source_name(ctx) -> str:
    """A name matching the pattern EventBridge requires for partner event source names."""
    suffix = ctx.unique_name("src-").strip("-")
    return f"aws.partner/sim2real.test/{suffix}"


def _error_code_and_message(fn):
    try:
        fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError("expected ClientError, call succeeded")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

