"""update-archive-pattern-is-mirrored-into-its-managed-rule-and-delete-removes-it."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-archive-pattern-is-mirrored-into-its-managed-rule-and-delete-removes-it"
GROUP = "archive"
SERVICES = ["events"]

_RULE_APPEAR_TIMEOUT_S = 60.0
_RULE_CONVERGE_TIMEOUT_S = 60.0
_ARCHIVE_DELETE_TIMEOUT_S = 180.0


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateArchive rewrites the pattern of the archive's managed rule (plus the replay exclusion),
    an empty pattern leaves only the exclusion, and DeleteArchive removes the rule.
    """
    events = ctx.client("events")

    bus = ctx.unique_name("sim2real-behav-bus-")
    bus_arn = events.create_event_bus(
        Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    first = ctx.unique_name("sim2real.first.")
    second = ctx.unique_name("sim2real.second.")
    archive = ctx.unique_name("sim2real-arc-")
    events.create_archive(
        ArchiveName=archive, EventSourceArn=bus_arn, EventPattern=json.dumps({"source": [first]})
    )
    ctx.on_cleanup(lambda: _delete_archive_and_wait(events, archive, missing_ok=True))
    managed = f"Events-Archive-{archive}"
    exclusion = {"replay-name": [{"exists": False}]}

    rule = _poll_for_rule(events, bus, managed)
    assert json.loads(rule["EventPattern"]) == {"source": [first], **exclusion}, (
        f"before any update the managed rule must mirror the archive pattern plus the replay "
        f"exclusion, got {rule['EventPattern']!r}"
    )

    new_pattern = {"source": [second], "detail-type": ["sim2real-archived"]}
    events.update_archive(ArchiveName=archive, EventPattern=json.dumps(new_pattern))
    described = events.describe_archive(ArchiveName=archive)
    assert json.loads(described["EventPattern"]) == new_pattern, (
        f"DescribeArchive after UpdateArchive reports {described.get('EventPattern')!r}, expected "
        f"{new_pattern!r}"
    )
    updated = _poll_rule_pattern(events, bus, managed, {**new_pattern, **exclusion})
    assert updated["State"] == "ENABLED", (
        f"UpdateArchive left the managed rule in state {updated['State']!r}"
    )

    # An empty EventPattern clears the archive's pattern; DescribeArchive then omits the field.
    events.update_archive(ArchiveName=archive, EventPattern="")
    cleared = events.describe_archive(ArchiveName=archive)
    assert "EventPattern" not in cleared, (
        f"an empty EventPattern must clear the archive's pattern, but DescribeArchive still "
        f"reports {cleared.get('EventPattern')!r}"
    )
    _poll_rule_pattern(events, bus, managed, exclusion)

    _delete_archive_and_wait(events, archive)
    deadline = time.monotonic() + _RULE_CONVERGE_TIMEOUT_S
    remaining = None
    while time.monotonic() < deadline:
        remaining = [
            r["Name"]
            for page in events.get_paginator("list_rules").paginate(
                EventBusName=bus, NamePrefix="Events-Archive-"
            )
            for r in page["Rules"]
        ]
        if not remaining:
            break
        time.sleep(3)
    assert remaining == [], (
        f"DeleteArchive must remove the archive's managed rule; bus {bus!r} still lists "
        f"{remaining!r} {_RULE_CONVERGE_TIMEOUT_S}s later"
    )
    code, message = _error(lambda: events.describe_rule(Name=managed, EventBusName=bus))
    expected = ("ResourceNotFoundException", f"Rule {managed} does not exist on EventBus {bus}.")
    assert (code, message) == expected, (
        f"DescribeRule on the deleted archive's managed rule gave {code!r}: {message!r}, "
        f"expected {expected!r}"
    )


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_rule_pattern(events, bus: str, name: str, expected: dict) -> dict:
    deadline = time.monotonic() + _RULE_CONVERGE_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = events.describe_rule(Name=name, EventBusName=bus)
        if json.loads(last.get("EventPattern") or "null") == expected:
            return last
        time.sleep(2)
    raise AssertionError(
        f"the archive's managed rule {name!r} never converged to pattern {expected!r} within "
        f"{_RULE_CONVERGE_TIMEOUT_S}s; last read {last.get('EventPattern') if last else None!r}"
    )


def _poll_for_rule(events, bus: str, name: str) -> dict:
    deadline = time.monotonic() + _RULE_APPEAR_TIMEOUT_S
    while time.monotonic() < deadline:
        for page in events.get_paginator("list_rules").paginate(
            EventBusName=bus, NamePrefix="Events-Archive-"
        ):
            for rule in page["Rules"]:
                if rule["Name"] == name:
                    return rule
        time.sleep(2)
    raise AssertionError(
        f"CreateArchive never produced its managed rule {name!r} on bus {bus!r} within "
        f"{_RULE_APPEAR_TIMEOUT_S}s"
    )


def _delete_archive_and_wait(events, name: str, *, missing_ok: bool = False) -> None:
    """DeleteArchive is asynchronous and the bus cannot be deleted while it still exists."""
    try:
        events.delete_archive(ArchiveName=name)
    except ClientError as exc:
        if not (missing_ok and exc.response["Error"]["Code"] == "ResourceNotFoundException"):
            raise
    deadline = time.monotonic() + _ARCHIVE_DELETE_TIMEOUT_S
    while time.monotonic() < deadline:
        try:
            events.describe_archive(ArchiveName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(3)
    raise AssertionError(f"archive {name} still exists {_ARCHIVE_DELETE_TIMEOUT_S}s after DeleteArchive")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
