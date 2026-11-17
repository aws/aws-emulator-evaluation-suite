"""update-archive-round-trips-fields-and-rejects-bad-pattern-and-unknown-name."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-archive-round-trips-fields-and-rejects-bad-pattern-and-unknown-name"
GROUP = "archive"
SERVICES = ["events"]


@tags("axis:rejection", "cap:c1", "concern:representation", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """UpdateArchive's Description/RetentionDays change round-trips through DescribeArchive and
    ListArchives while EventSourceArn and EventPattern stay put; an invalid EventPattern is
    refused and leaves Description untouched; an unknown ArchiveName is refused by name.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_UpdateArchive.html
    """
    events = ctx.client("events")

    bus = ctx.unique_name("sim2real-behav-bus-")
    bus_arn = events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])[
        "EventBusArn"
    ]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    archive_name = ctx.unique_name("sim2real-behav-archive-")
    original_pattern = {"source": ["sim2real.archive.original"]}
    original_json = json.dumps(original_pattern)
    events.create_archive(
        ArchiveName=archive_name,
        EventSourceArn=bus_arn,
        Description="initial description",
        EventPattern=original_json,
        RetentionDays=1,
    )
    ctx.on_cleanup(lambda: _delete_archive_and_wait(events, archive_name))

    created = _poll_until(
        lambda: events.describe_archive(ArchiveName=archive_name),
        lambda d: d.get("State") in ("ENABLED", "CREATE_FAILED", "DISABLED"),
        timeout_s=300.0,
        interval_s=3.0,
        description=f"archive {archive_name} leaving CREATING",
    )
    assert created["State"] == "ENABLED", f"archive settled at State={created['State']!r}: {created!r}"

    # Change exactly Description and RetentionDays; EventPattern is omitted from the request.
    events.update_archive(
        ArchiveName=archive_name, Description="updated description", RetentionDays=7
    )
    updated = _poll_until(
        lambda: events.describe_archive(ArchiveName=archive_name),
        lambda d: d.get("RetentionDays") == 7,
        timeout_s=60.0,
        interval_s=2.0,
        description=f"archive {archive_name} reflecting RetentionDays=7",
    )
    assert updated["Description"] == "updated description", (
        f"expected Description 'updated description' after UpdateArchive, got "
        f"{updated['Description']!r}: {updated!r}"
    )
    assert updated["RetentionDays"] == 7, (
        f"expected RetentionDays 7 after UpdateArchive, got {updated['RetentionDays']!r}: {updated!r}"
    )
    assert updated["EventPattern"] == original_json, (
        f"UpdateArchive without an EventPattern must leave it at {original_json!r}, got "
        f"{updated['EventPattern']!r}"
    )
    assert updated["EventSourceArn"] == bus_arn, (
        f"UpdateArchive must never change EventSourceArn; expected {bus_arn!r}, got "
        f"{updated['EventSourceArn']!r}"
    )

    listed = _list_archive_entries(events, bus_arn, archive_name)
    assert listed["RetentionDays"] == 7, (
        f"ListArchives entry for {archive_name!r} shows RetentionDays="
        f"{listed['RetentionDays']!r}, expected 7 to match DescribeArchive: {listed!r}"
    )

    # Break exactly one thing: an unrecognised matcher operator inside an otherwise well-formed
    # pattern.
    bad_pattern = {"source": ["sim2real.archive.original"], "detail": {"n": [{"nosuchop": [1]}]}}
    bad_json = json.dumps(bad_pattern)
    _bad_pattern_refusal = (
        "InvalidEventPatternException",
        f"Event pattern is not valid. Reason: Unrecognized match type nosuchop\n at [Source: "
        f"(String)\"{bad_json}\"; line: 1, column: {bad_json.index('[1]') + 2}]",
    )
    expect_error(lambda: events.update_archive(ArchiveName=archive_name, EventPattern=bad_json),
                 *_bad_pattern_refusal)

    after_bad = events.describe_archive(ArchiveName=archive_name)
    assert after_bad["Description"] == "updated description", (
        f"the refused UpdateArchive must leave Description at 'updated description', got "
        f"{after_bad['Description']!r}: {after_bad!r}"
    )
    assert after_bad["EventPattern"] == original_json, (
        f"the refused UpdateArchive must leave EventPattern at {original_json!r}, got "
        f"{after_bad['EventPattern']!r}"
    )
    assert after_bad["RetentionDays"] == 7, (
        f"the refused UpdateArchive must leave RetentionDays at 7, got "
        f"{after_bad['RetentionDays']!r}: {after_bad!r}"
    )

    # Positive control next to the refusal: the same construct corrected is accepted and takes
    # effect, proving the refusal above is specific to the bad operator.
    good_pattern = {"source": ["sim2real.archive.updated"]}
    good_json = json.dumps(good_pattern)
    events.update_archive(ArchiveName=archive_name, EventPattern=good_json)
    after_good = _poll_until(
        lambda: events.describe_archive(ArchiveName=archive_name),
        lambda d: d.get("EventPattern") == good_json,
        timeout_s=60.0,
        interval_s=2.0,
        description=f"archive {archive_name} reflecting the corrected EventPattern",
    )
    assert after_good["EventPattern"] == good_json, (
        f"expected EventPattern {good_json!r} after the corrected UpdateArchive, got "
        f"{after_good['EventPattern']!r}"
    )

    # UpdateArchive on a name nothing ever created.
    never_created = ctx.unique_name("sim2real-behav-archive-never-")
    _unknown_name_refusal = (
        "ResourceNotFoundException",
        f"Archive {never_created} does not exist.",
    )
    expect_error(
        lambda: events.update_archive(ArchiveName=never_created, Description="unreachable"),
        *_unknown_name_refusal,
    )

    # Positive control next to the refusal: the real archive is unaffected and still answers.
    control = events.describe_archive(ArchiveName=archive_name)
    assert control["EventPattern"] == good_json, (
        f"the real archive {archive_name!r} must still be readable and unaffected by the "
        f"UpdateArchive on {never_created!r}, got EventPattern={control['EventPattern']!r}"
    )


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; raise on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


def _list_archive_entries(events, bus_arn: str, archive_name: str) -> dict:
    """The ListArchives entry named ``archive_name`` under ``bus_arn``, following NextToken."""
    token = None
    while True:
        kwargs = {"EventSourceArn": bus_arn}
        if token:
            kwargs["NextToken"] = token
        page = events.list_archives(**kwargs)
        for entry in page.get("Archives", []):
            if entry["ArchiveName"] == archive_name:
                return entry
        token = page.get("NextToken")
        if not token:
            raise AssertionError(
                f"archive {archive_name!r} is absent from ListArchives over {bus_arn!r}"
            )


def _delete_archive_and_wait(events, name: str, *, timeout_s: float = 180.0) -> None:
    """Delete an archive and wait for it to be gone: the event bus cannot be deleted while an
    archive still references it."""
    try:
        events.delete_archive(ArchiveName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            events.describe_archive(ArchiveName=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        time.sleep(3)
    raise AssertionError(f"archive {name} still present {timeout_s}s after DeleteArchive")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
