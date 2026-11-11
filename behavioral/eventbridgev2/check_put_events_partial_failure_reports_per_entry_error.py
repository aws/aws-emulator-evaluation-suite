"""put-events-partial-failure-reports-per-entry-error."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-events-partial-failure-reports-per-entry-error"
GROUP = "put-events"
SERVICES = ["eventbridgev2"]

_ACTIVE_TIMEOUT_S = 60.0


def _teardown_bus(ebv2, bus_arn: str):
    """Delete the bus, waiting out a transient CREATING/DELETING rather than hiding it."""

    def run_undo() -> None:
        deadline = time.monotonic() + _ACTIVE_TIMEOUT_S
        while True:
            try:
                ebv2.delete_event_bus(EventBusArn=bus_arn)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code != "InvalidStateException" or time.monotonic() > deadline:
                    raise
                time.sleep(2)

    return run_undo


def _wait_bus_active(ebv2, bus_arn: str) -> None:
    deadline = time.monotonic() + _ACTIVE_TIMEOUT_S
    while True:
        described = ebv2.describe_event_bus(EventBusArn=bus_arn)
        if described["State"] == "ACTIVE":
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"bus stayed {described['State']!r}, never reached ACTIVE")
        time.sleep(2)


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutEvents with one well-formed entry and one entry whose Detail is not JSON publishes the
    good entry and reports the bad one's own error, rather than failing the whole batch.
    """
    ebv2 = ctx.client("eventbridgev2")
    bus_name = ctx.unique_name("sim2real-behav-ebv2-bus-")

    bus = ebv2.create_event_bus(Name=bus_name, ClientToken=ctx.unique_name("sim2real-behav-tok-"))
    bus_arn = bus["EventBusArn"]
    ctx.on_cleanup(_teardown_bus(ebv2, bus_arn))
    _wait_bus_active(ebv2, bus_arn)

    put = ebv2.put_events(EventBusArn=bus_arn, Entries=[
        {"Source": "sim2real.ebv2.partial", "DetailType": "ok", "Detail": json.dumps({"a": 1})},
        {"Source": "sim2real.ebv2.partial", "DetailType": "bad", "Detail": "not-json"},
    ])

    assert put["FailedEntryCount"] == 1, (
        f"expected exactly one failed entry, got FailedEntryCount={put['FailedEntryCount']!r}: "
        f"{put['Entries']!r}"
    )
    good, bad = put["Entries"]
    assert "EventId" in good and good.get("SuccessCode") == "PUBLISHED", (
        f"the well-formed entry must still publish, got {good!r}"
    )
    assert bad.get("ErrorCode") == "MalformedDetail", (
        f"expected ErrorCode 'MalformedDetail' on the bad entry, got {bad!r}"
    )
    assert bad.get("ErrorMessage") == "Detail is not valid JSON", (
        f"unexpected ErrorMessage {bad.get('ErrorMessage')!r}"
    )
    assert "EventId" not in bad, f"a failed entry must carry no EventId, got {bad!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
