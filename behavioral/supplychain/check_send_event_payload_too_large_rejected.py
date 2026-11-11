"""send-event-payload-too-large-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-event-payload-too-large-rejected"
GROUP = "overly-permissive"
SERVICES = ["supplychain"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendDataIntegrationEvent rejects a data payload over the documented 1 MiB limit with
    ValidationException and returns no eventId, while an otherwise identical, small payload on
    the same eventGroupId succeeds."""
    sc = ctx.client("supplychain", region="us-east-1")  # AWS Supply Chain is not available in us-west-2
    instance_id = _create_active_instance(ctx, sc)
    event_group_id = ctx.unique_name("sim2real-sc-evtgrp-")

    # scn.data.shipment requires these fields; a payload missing any of them is rejected for a
    # schema reason that has nothing to do with size, so both payloads below carry every one and
    # differ only in the length of "id" -- isolating size as the sole variable under test.
    base_fields = {
        "supplier_tpartner_id": "sim2real-partner-1",
        "product_id": "sim2real-product-1",
        "order_id": "sim2real-order-1",
        "order_line_id": "sim2real-line-1",
        "package_id": "sim2real-package-1",
    }
    oversized_payload = json.dumps({**base_fields, "id": "x" * (1024 * 1024 + 100)})
    assert len(oversized_payload) > 1024 * 1024

    result = {}

    def _send_oversized():
        result["response"] = sc.send_data_integration_event(
            instanceId=instance_id,
            eventType="scn.data.shipment",
            eventGroupId=event_group_id,
            data=oversized_payload,
        )

    code, message = _error(_send_oversized)
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        "1 validation error detected: Value at 'data' failed to satisfy constraint: "
        "Member must have length less than or equal to 1048576"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"
    assert "response" not in result, "an eventId was returned despite the oversized payload"

    events_after_rejection = {
        e["eventGroupId"] for e in sc.list_data_integration_events(instanceId=instance_id)["events"]
    }
    assert event_group_id not in events_after_rejection, (
        "the rejected oversized event's eventGroupId is visible in ListDataIntegrationEvents"
    )

    small_payload = json.dumps({**base_fields, "id": "sim2real-1"})
    sent = sc.send_data_integration_event(
        instanceId=instance_id,
        eventType="scn.data.shipment",
        eventGroupId=event_group_id,
        data=small_payload,
    )
    event_id = sent["eventId"]
    assert event_id

    fetched = sc.get_data_integration_event(instanceId=instance_id, eventId=event_id)["event"]
    assert fetched["eventGroupId"] == event_group_id, (
        f"expected eventGroupId {event_group_id!r}, got {fetched.get('eventGroupId')!r}"
    )
    assert fetched["eventType"] == "scn.data.shipment", (
        f"expected eventType 'scn.data.shipment', got {fetched.get('eventType')!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError code and message. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_active_instance(ctx, sc):
    name = ctx.unique_name("sim2real-sc-")
    instance = sc.create_instance(
        instanceName=name,
        instanceDescription="sim2real behavioral check",
        tags={"team": "sim2real"},
    )["instance"]
    instance_id = instance["instanceId"]

    def _cleanup():
        try:
            sc.delete_instance(instanceId=instance_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    result = _poll_until(
        lambda: sc.get_instance(instanceId=instance_id)["instance"],
        lambda inst: inst["state"] in ("Active", "CreateFailed"),
        timeout_s=1200.0,
        interval_s=15.0,
    )
    if result["state"] != "Active":
        raise AssertionError(f"instance did not reach Active state: {result}")
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
