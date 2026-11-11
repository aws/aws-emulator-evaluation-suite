"""delete-event-bus-blocked-while-an-archive-targets-it."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-event-bus-blocked-while-an-archive-targets-it"
GROUP = "archive"
SERVICES = ["events"]

_ARCHIVE_ENABLED_TIMEOUT_S = 90.0
_ARCHIVE_GONE_TIMEOUT_S = 180.0
_BUS_GONE_TIMEOUT_S = 60.0

# The one code real EventBridge returns for "this bus still has a rule" (archives included).
_EXPECTED_BLOCK_CODE = "ValidationException"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An event bus with an attached archive cannot be deleted (ValidationException, "has rules"),
    and the identical DeleteEventBus succeeds once the archive is deleted.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_DeleteEventBus.html
    """
    events = ctx.client("events")

    # Positive control: DeleteEventBus works on a bus with nothing attached.
    control_bus = _bus_name(ctx)
    control_arn = events.create_event_bus(Name=control_bus, Tags=_tags_kv())["EventBusArn"]
    ctx.on_cleanup(lambda n=control_bus: _delete_bus_quietly(ctx, n))
    assert control_arn.endswith(f"/{control_bus}"), (
        f"CreateEventBus must return an ARN ending in /{control_bus}, got {control_arn!r}"
    )
    events.delete_event_bus(Name=control_bus)
    control_code = _poll_until(
        lambda: _error_code(lambda: events.describe_event_bus(Name=control_bus)),
        lambda c: c == "ResourceNotFoundException",
        timeout_s=_BUS_GONE_TIMEOUT_S,
        interval_s=2.0,
        description=f"control bus {control_bus} disappears after DeleteEventBus",
    )
    assert control_code == "ResourceNotFoundException", (
        f"positive control failed: after DeleteEventBus({control_bus}) DescribeEventBus must return "
        f"ResourceNotFoundException, got {control_code!r} — DeleteEventBus is not working in this "
        f"account/region, so the refusal asserted below would prove nothing"
    )

    bus = _bus_name(ctx)
    bus_arn = events.create_event_bus(Name=bus, Tags=_tags_kv())["EventBusArn"]
    ctx.on_cleanup(lambda n=bus: _delete_bus_quietly(ctx, n))

    archive = _archive_name(ctx)
    events.create_archive(
        ArchiveName=archive,
        EventSourceArn=bus_arn,
        Description="sim2real delete-bus-blocked-by-archive",
        EventPattern=json.dumps({"source": [{"prefix": "sim2real."}]}),
        RetentionDays=1,
    )
    ctx.on_cleanup(lambda a=archive: _delete_archive_and_wait(ctx, a))
    enabled = _poll_until(
        lambda: events.describe_archive(ArchiveName=archive),
        lambda d: d["State"] in ("ENABLED", "CREATE_FAILED"),
        timeout_s=_ARCHIVE_ENABLED_TIMEOUT_S,
        interval_s=2.0,
        description=f"archive {archive} leaves CREATING",
    )
    assert enabled["State"] == "ENABLED", (
        f"archive {archive} must reach ENABLED before the dependency can be tested, got "
        f"State={enabled['State']!r} StateReason={enabled.get('StateReason')!r}"
    )
    assert enabled["EventSourceArn"] == bus_arn, (
        f"the archive must report the bus it was created from: expected EventSourceArn={bus_arn!r}, "
        f"got {enabled.get('EventSourceArn')!r}"
    )

    code, message, status = _error(
        lambda: events.delete_event_bus(Name=bus),
        f"DeleteEventBus({bus}) while archive {archive} still referenced it (an unconditional "
        f"delete orphans the archive; this is the over-permissive failure the check exists to "
        f"catch)",
    )
    assert code == _EXPECTED_BLOCK_CODE, (
        f"expected the archive dependency refusal to be {_EXPECTED_BLOCK_CODE!r}, got {code!r} "
        f"with message {message!r}"
    )
    # The message is the generic "has rules" refusal: CreateArchive provisions a hidden managed rule
    # (Events-Archive-<name>) on the source bus, and that rule is what DeleteEventBus detects.
    assert status == 400, f"the archive dependency refusal carried HTTP {status!r}, expected 400"
    assert message, f"the archive dependency refusal carried an empty message (code={code!r})"
    rules_on_bus = events.list_rules(EventBusName=bus).get("Rules", [])
    managed_rule_name = f"Events-Archive-{archive}"
    managed_rule = next((r for r in rules_on_bus if r.get("Name") == managed_rule_name), None)
    assert managed_rule is not None, (
        f"CreateArchive({archive}) must provision a managed rule named {managed_rule_name!r} on "
        f"{bus!r} — that hidden rule is the actual dependency DeleteEventBus refuses to break; "
        f"ListRules(EventBusName={bus!r}) returned {rules_on_bus!r}"
    )
    assert managed_rule.get("ManagedBy"), (
        f"the archive's hidden rule must be reported as service-managed (non-empty ManagedBy), "
        f"got rule {managed_rule!r}"
    )

    still_there = events.describe_event_bus(Name=bus)
    assert still_there["Arn"] == bus_arn, (
        f"the refused delete must leave the bus untouched: expected Arn={bus_arn!r}, got "
        f"{still_there.get('Arn')!r}"
    )
    listed = _bus_names(events, bus)
    assert bus in listed, (
        f"the refused delete must leave the bus in ListEventBuses(NamePrefix={bus!r}); got {listed}"
    )
    archive_after = events.describe_archive(ArchiveName=archive)
    assert archive_after["State"] == "ENABLED", (
        f"the refused delete must leave the archive ENABLED, got {archive_after['State']!r}"
    )

    # Deleting the archive must also remove its managed rule.
    events.delete_archive(ArchiveName=archive)
    gone_code = _poll_until(
        lambda: _error_code(lambda: events.describe_archive(ArchiveName=archive)),
        lambda c: c == "ResourceNotFoundException",
        timeout_s=_ARCHIVE_GONE_TIMEOUT_S,
        interval_s=3.0,
        description=f"archive {archive} disappears after DeleteArchive",
    )
    assert gone_code == "ResourceNotFoundException", (
        f"DescribeArchive({archive}) must return ResourceNotFoundException once the archive is "
        f"deleted, got {gone_code!r}"
    )
    rules_after_restore = [
        r["Name"] for r in events.list_rules(EventBusName=bus).get("Rules", [])
    ]
    assert managed_rule_name not in rules_after_restore, (
        f"deleting the archive must remove its hidden managed rule {managed_rule_name!r} from "
        f"{bus!r} too; ListRules(EventBusName={bus!r}) still returned {rules_after_restore!r}"
    )

    events.delete_event_bus(Name=bus)
    final_code = _poll_until(
        lambda: _error_code(lambda: events.describe_event_bus(Name=bus)),
        lambda c: c == "ResourceNotFoundException",
        timeout_s=_BUS_GONE_TIMEOUT_S,
        interval_s=2.0,
        description=f"bus {bus} disappears once its archive is gone",
    )
    assert final_code == "ResourceNotFoundException", (
        f"after the archive was removed the identical DeleteEventBus({bus}) must succeed and leave "
        f"DescribeEventBus returning ResourceNotFoundException, got {final_code!r}"
    )
    _, final_message, final_status = _error(
        lambda: events.describe_event_bus(Name=bus), f"DescribeEventBus({bus}) after delete")
    assert final_status == 400, f"DescribeEventBus on the deleted bus carried HTTP {final_status!r}, expected 400"
    assert bus in final_message, (
        f"DescribeEventBus on the deleted bus must name {bus!r}, got {final_message!r}")
    assert _bus_names(events, bus) == [], (
        f"the deleted bus must be absent from ListEventBuses(NamePrefix={bus!r}), got "
        f"{_bus_names(events, bus)}"
    )
    # Cleanup is registered before the call so an unexpected success does not leak the archive.
    orphan_archive = _archive_name(ctx)
    ctx.on_cleanup(lambda a=orphan_archive: _delete_archive_and_wait(ctx, a))
    mutate_code, mutate_message, mutate_status = _error(
        lambda: events.create_archive(
            ArchiveName=orphan_archive, EventSourceArn=bus_arn, RetentionDays=1
        ),
        f"CreateArchive against the deleted bus {bus_arn}",
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"CreateArchive against the deleted bus {bus_arn!r} must fail with "
        f"ResourceNotFoundException, got {mutate_code!r}"
    )
    assert mutate_status == 400, f"CreateArchive on the deleted bus carried HTTP {mutate_status!r}, expected 400"
    expected_message = f"Event bus {bus} does not exist."
    assert mutate_message == expected_message, f"expected the message {expected_message!r}, got {mutate_message!r}"


_PREFIX = "sim2real-behav-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _tags_kv() -> list[dict[str, str]]:
    return [
        {"Key": _MANAGED_TAG_KEY, "Value": "true"},
        {"Key": "sim2real:prefix", "Value": _PREFIX.rstrip("-")},
    ]


def _bus_name(ctx) -> str:
    return ctx.unique_name(f"{_PREFIX}bus-")


def _archive_name(ctx) -> str:
    """ArchiveName is capped at 48 characters by real EventBridge, so the kind token stays short."""
    return ctx.unique_name(f"{_PREFIX}ar-")[:48]


def _error(fn, what: str = "the call") -> tuple[str, str, int | None]:
    """(error code, message, HTTP status) for a call expected to fail; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return (err.get("Code"), err.get("Message") or "",
                exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"))
    raise AssertionError(f"{what} SUCCEEDED where real EventBridge refuses it: {result!r}")


def _error_code(fn) -> str | None:
    """A poll probe: the error code fn() raises, or "present" while the read still succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "present"


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll until predicate holds; RAISE on timeout (never return the last value)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _bus_names(events, prefix: str) -> list[str]:
    return [b["Name"] for b in events.list_event_buses(NamePrefix=prefix).get("EventBuses", [])]


def _delete_archive_and_wait(ctx, name: str) -> None:
    """Teardown: delete the archive and wait, because the bus teardown depends on it.
    Only ResourceNotFoundException is tolerated; any other failure raises."""
    events = ctx.client("events")
    try:
        events.delete_archive(ArchiveName=name)
    except events.exceptions.ResourceNotFoundException:
        pass
    except ClientError as exc:
        raise AssertionError(f"could not delete archive {name}: {exc.response['Error']['Code']}") from exc
    deadline = time.monotonic() + _ARCHIVE_GONE_TIMEOUT_S
    while time.monotonic() < deadline:
        try:
            events.describe_archive(ArchiveName=name)
        except events.exceptions.ResourceNotFoundException:
            return
        except ClientError:
            pass
        time.sleep(3)
    raise AssertionError(f"archive {name} still present {_ARCHIVE_GONE_TIMEOUT_S}s after DeleteArchive")


def _delete_bus_quietly(ctx, name: str) -> None:
    """Teardown: the bus may already be gone (the body deletes two of them on the happy path);
    only ResourceNotFoundException is tolerated, any other failure raises."""
    events = ctx.client("events")
    try:
        events.delete_event_bus(Name=name)
    except events.exceptions.ResourceNotFoundException:
        pass
    except ClientError as exc:
        raise AssertionError(f"could not delete event bus {name}: {exc.response['Error']['Code']}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
