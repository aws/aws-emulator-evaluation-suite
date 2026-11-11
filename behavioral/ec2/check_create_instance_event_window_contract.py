"""create-instance-event-window-contract."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-instance-event-window-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateInstanceEventWindow persists the requested cron expression
    verbatim and transitions to 'active', and rejects a cron expression whose
    combined coverage is below the documented 4-hour minimum.
    """
    ec2 = ctx.client("ec2")
    cron_expression = "* 0-4,20-23 * * 1,5"

    resp = ec2.create_instance_event_window(
        Name=ctx.unique_name("sim2real-behav-"),
        CronExpression=cron_expression,
        TagSpecifications=[_tag_spec(ctx, "instance-event-window")],
    )
    window = resp["InstanceEventWindow"]
    window_id = window["InstanceEventWindowId"]
    ctx.on_cleanup(
        lambda: ec2.delete_instance_event_window(InstanceEventWindowId=window_id, ForceDelete=True)
    )

    assert window["CronExpression"] == cron_expression, (
        f"expected the stored CronExpression to be {cron_expression!r} verbatim, got {window['CronExpression']!r}"
    )
    assert window["State"] in ("creating", "active"), (
        f"expected a freshly created event window to be 'creating' or 'active', got {window['State']!r}"
    )

    state = _poll_until(
        lambda: ec2.describe_instance_event_windows(InstanceEventWindowIds=[window_id])[
            "InstanceEventWindows"
        ][0]["State"],
        lambda s: s == "active",
        timeout_s=60.0,
        interval_s=3.0,
        description="event window reaching 'active'",
    )
    assert state == "active", f"expected the event window to become active, got {state!r}"

    # Error boundary: a window whose total coverage is under 4 hours must be
    # rejected, and must not create a partial/degenerate window.
    short_cron = "* 10 * * 1"
    rejected_spec = _tag_spec(ctx, "instance-event-window")
    rejected_tag = rejected_spec["Tags"][0]
    error = _client_error(
        lambda: ec2.create_instance_event_window(
            CronExpression=short_cron, TagSpecifications=[rejected_spec]
        )
    )
    assert error.get("Code") == "InvalidInstanceEventWindowCronExpression", (
        f"expected InvalidInstanceEventWindowCronExpression for a sub-4-hour window, got {error.get('Code')!r}"
    )
    expected_message = f"Invalid Cron Expression {short_cron}."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )
    created = [
        w["InstanceEventWindowId"]
        for page in ec2.get_paginator("describe_instance_event_windows").paginate()
        for w in page["InstanceEventWindows"]
        if rejected_tag in (w.get("Tags") or [])
    ]
    assert created == [], f"a rejected CreateInstanceEventWindow must not create a resource: {created!r}"


def _client_error(fn):
    """Call *fn*; return its botocore Error dict. An unexpected SUCCESS is the strongest
    possible signal, so it raises rather than returning a sentinel a code compare would blur."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _tag_spec(ctx, resource_type):
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-behav-{resource_type}-")}],
    }


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
