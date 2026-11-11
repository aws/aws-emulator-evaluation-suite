"""e2e-partner-event-source-activation-to-ingestion-flow."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "e2e-partner-event-source-activation-to-ingestion-flow"
GROUP = "e2e"
SERVICES = ["events"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A non-partner account's CreatePartnerEventSource is rejected with ValidationException, the
    source then describes as not found, and PutPartnerEvents through it fails per entry with
    InvalidArgument, while the same credentials create a custom bus and deliver PutEvents to it."""
    events = ctx.client("events")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    partner = ctx.unique_name("sim2real-partner-").replace("_", "-")
    generator = ctx.unique_name("src-")
    source_name = f"aws.partner/{partner}/{generator}"

    from botocore.exceptions import ClientError

    try:
        events.create_partner_event_source(Name=source_name, Account=account_id)
        ctx.on_cleanup(lambda: _ignore_not_found(lambda: events.delete_partner_event_source(Name=source_name, Account=account_id)))
        created = True
    except ClientError as exc:
        created = False
        create_err = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
        assert create_err == ("ValidationException", _not_allowlisted(source_name)), (
            f"expected ValidationException for a non-allowlisted partner namespace, got {create_err!r}"
        )

    assert not created, (
        "CreatePartnerEventSource unexpectedly succeeded for a non-whitelisted caller account -- "
        "this account has no partner rights to this namespace"
    )

    # Because creation was rejected, the event source must not exist on the customer side
    # either -- no activation/ingestion state should have leaked into existence.
    err = _error(lambda: events.describe_event_source(Name=source_name))
    assert err == ("ResourceNotFoundException", f"Event source {source_name} does not exist."), (
        f"expected no event source to exist after a rejected CreatePartnerEventSource, got {err!r}"
    )

    # And PutPartnerEvents through the never-created source must fail per-entry rather than
    # being accepted as if the source existed.
    resp = _put_partner_event(events, source_name)
    assert resp["FailedEntryCount"] == 1
    entry = resp["Entries"][0]
    assert "EventId" not in entry
    assert (entry.get("ErrorCode"), entry.get("ErrorMessage")) == (
        "InvalidArgument",
        "Parameter Source is not valid. Reason: Caller AWS account is not whitelisted for the source.",
    ), entry

    # Positive control: the exact same credentials can still create, describe and deliver to an
    # ordinary (non-partner) bus -- proving the rejections above are a targeted partner-namespace
    # boundary, not a broken client or a blanket deny that would make every assertion above vacuous.
    bus_name = ctx.unique_name("sim2real-bus-")
    events.create_event_bus(Name=bus_name)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: events.delete_event_bus(Name=bus_name)))
    described = events.describe_event_bus(Name=bus_name)
    assert described["Name"] == bus_name, described
    put_result = events.put_events(
        Entries=[
            {
                "Source": "sim2real.control",
                "DetailType": "sim2real-control",
                "Detail": "{\"ok\": true}",
                "EventBusName": bus_name,
            }
        ]
    )
    assert put_result["FailedEntryCount"] == 0, put_result
    assert "EventId" in put_result["Entries"][0], put_result


# ===== helpers =====
def _not_allowlisted(name: str) -> str:
    """EventBridge's refusal for a caller outside a partner namespace; it names
    aws.partner/<namespace>, the first two segments of the source name or prefix."""
    namespace = "/".join(name.split("/")[:2])
    return f"Caller is not whitelisted for the event source partner namespace {namespace}"


def _put_partner_event(events_client, source_name: str) -> dict:
    return events_client.put_partner_events(
        Entries=[
            {
                "Time": datetime.now(timezone.utc),
                "Source": source_name,
                "DetailType": "sim2real-partner-test",
                "Detail": "{\"ok\": true}",
            }
        ]
    )


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met within {timeout_s}s, last value={last!r}")


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """(code, message) of a call that must fail; a call that succeeds raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _ignore_not_found(fn: Callable[[], Any]) -> None:
    """Run a teardown delete; only an already-gone resource is not an error."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
