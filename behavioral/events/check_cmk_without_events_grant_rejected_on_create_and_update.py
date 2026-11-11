"""cmk-without-events-grant-rejected-on-create-and-update."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cmk-without-events-grant-rejected-on-create-and-update"
GROUP = "event-bus"
SERVICES = ["events"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A KMS key whose policy does not grant events.amazonaws.com is refused with AccessDenied on
    CreateEventBus (no bus is created) and UpdateEventBus (key unchanged); a granted key works."""
    events = ctx.client("events")
    kms = ctx.client("kms")

    granted_key = _create_key(ctx, kms, grant_events=True)
    ungranted_key = _create_key(ctx, kms, grant_events=False)
    denied_message = (
        "Access to call kms:GenerateDataKey is denied. Reason: events.amazonaws.com is not "
        f"authorized to perform: kms:GenerateDataKey on {ungranted_key} because the resource does "
        "not exist in this Region, no resource-based policies allow access, or a resource-based "
        "policy explicitly denies access"
    )

    # --- CreateEventBus with the ungranted key is refused, and no bus exists afterwards. ---
    refused_bus = ctx.unique_name("sim2real-behav-bus-")
    ctx.on_cleanup(lambda: _delete_bus_if_present(events, refused_bus))
    code, message = _error(lambda: events.create_event_bus(Name=refused_bus, KmsKeyIdentifier=ungranted_key))
    assert code == "AccessDeniedException", (
        f"CreateEventBus with a key EventBridge may not use must be refused with "
        f"AccessDeniedException, got {code!r} ({message!r})"
    )
    assert message == denied_message, f"refusal message was {message!r}, expected {denied_message!r}"
    absent_code, absent_message = _error(lambda: events.describe_event_bus(Name=refused_bus))
    assert (absent_code, absent_message) == (
        "ResourceNotFoundException", f"Event bus {refused_bus} does not exist."
    ), f"the refused CreateEventBus must create nothing; DescribeEventBus gave {absent_code!r} {absent_message!r}"

    # --- positive control: the granted key is accepted on create. ---
    bus = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus, KmsKeyIdentifier=granted_key, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))
    assert events.describe_event_bus(Name=bus).get("KmsKeyIdentifier") == granted_key, (
        "a bus created with a key that grants EventBridge must report that key"
    )

    # --- UpdateEventBus to the ungranted key is refused, and the bus keeps its key. ---
    code, message = _error(lambda: events.update_event_bus(Name=bus, KmsKeyIdentifier=ungranted_key))
    assert code == "AccessDeniedException", (
        f"UpdateEventBus to a key EventBridge may not use must be refused with "
        f"AccessDeniedException, got {code!r} ({message!r})"
    )
    assert message == denied_message, f"refusal message was {message!r}, expected {denied_message!r}"
    after = events.describe_event_bus(Name=bus).get("KmsKeyIdentifier")
    assert after == granted_key, (
        f"the refused update must leave the bus on its original key, but KmsKeyIdentifier is now "
        f"{'the refused key' if after == ungranted_key else repr(after)}"
    )


def _create_key(ctx, kms, *, grant_events: bool) -> str:
    statements = [{
        "Sid": "AccountAdmin",
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
        "Action": "kms:*",
        "Resource": "*",
    }]
    if grant_events:
        statements.append({
            "Sid": "AllowEventBridge",
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"],
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:SourceAccount": ctx.account}},
        })
    meta = kms.create_key(
        Description=f"sim2real {CHECK}",
        Policy=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta["Arn"]


def _delete_bus_if_present(events, name: str) -> None:
    """Teardown for the bus the refused create must not have made; deletes it if it exists."""
    try:
        events.describe_event_bus(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    events.delete_event_bus(Name=name)


def _error(fn) -> tuple[str, str]:
    """(code, message) of a call that must fail; an unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
