"""list-partner-event-sources-disabled-account-denied."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-partner-event-sources-disabled-account-denied"
GROUP = "overly-permissive"
SERVICES = ["events"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListPartnerEventSources from an account without partner access fails with
    ValidationException for a well-formed aws.partner/ prefix instead of returning a list,
    and leaves an ordinary event bus untouched and listable."""
    events = ctx.client("events")

    # A real, ordinary resource that the rejected call must have zero effect on.
    bus_name = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: events.delete_event_bus(Name=bus_name)))
    before = {bus["Name"] for bus in events.list_event_buses(NamePrefix=bus_name)["EventBuses"]}
    assert bus_name in before, f"expected {bus_name} in list_event_buses right after create, got {before}"

    prefix = f"aws.partner/{ctx.unique_name('sim2real-behav-partner-')}/"
    code, message = _error(lambda: events.list_partner_event_sources(NamePrefix=prefix))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == _not_allowlisted(prefix), f"unexpected message {message!r}"

    # Effect absent / no collateral damage: the rejected partner-scoped call left the check's
    # own ordinary bus exactly as it was.
    after = {bus["Name"] for bus in events.list_event_buses(NamePrefix=bus_name)["EventBuses"]}
    assert before == after, f"ListPartnerEventSources rejection had a side effect: before={before} after={after}"

    # Positive control: an ordinary (non-partner) listing operation still succeeds with the same
    # credentials and sees the real bus -- proving the rejection above is a targeted
    # partner-privilege check, not a broken client or blanket deny.
    assert bus_name in after, f"expected {bus_name} still in list_event_buses, got {after}"


def _not_allowlisted(name: str) -> str:
    """EventBridge's refusal for a caller outside a partner namespace; it names
    aws.partner/<namespace>, the first two segments of the source name or prefix."""
    namespace = "/".join(name.split("/")[:2])
    return f"Caller is not whitelisted for the event source partner namespace {namespace}"


def _error(fn):
    """(code, message) of a call that must fail; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
