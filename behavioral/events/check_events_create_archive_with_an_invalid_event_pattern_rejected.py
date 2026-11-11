"""events-create-archive-with-an-invalid-event-pattern-rejected."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-create-archive-with-an-invalid-event-pattern-rejected"

GROUP = "archive"

SERVICES = ["events"]


@tags("axis:rejection", "concern:eventing", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """CreateArchive with an unrecognised pattern operator fails with InvalidEventPatternException
    and creates nothing, while the corrected pattern yields an ENABLED archive that ingests an event.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_CreateArchive.html
    """
    events = ctx.client("events")
    source = _xname(ctx, "src").replace("-", ".")

    bus = _xname(ctx, "bus")
    bus_arn = events.create_event_bus(Name=bus, Tags=_xsvc_tags_kv())["EventBusArn"]
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus))

    # Break exactly one thing: an unrecognised matcher operator inside an otherwise well-formed
    # pattern. The name is valid, the EventSourceArn is valid, the JSON parses.
    rejected_name = _xname(ctx, "arc-bad")
    assert len(rejected_name) <= 48, (
        f"ArchiveName is capped at 48 characters by real AWS and this one is {len(rejected_name)}: "
        f"{rejected_name!r} -- a name-length rejection would mask the pattern rejection under test"
    )
    bad_pattern = {"source": [source], "detail": {"n": [{"nosuchop": [1]}]}}
    bad_json = json.dumps(bad_pattern)
    err, unexpected = _error(
        lambda: events.create_archive(
            ArchiveName=rejected_name,
            EventSourceArn=bus_arn,
            EventPattern=bad_json,
        )
    )
    if unexpected is not None:
        # The service wrongly accepted it, so the archive EXISTS -- register its teardown before the
        # assertion below aborts the check, or it leaks and blocks the bus delete.
        ctx.on_cleanup(lambda: _delete_archive_and_wait(ctx, rejected_name))
    # The parser echoes the pattern and the 1-based column just past the operator's first value.
    expected = (
        "InvalidEventPatternException",
        f"Event pattern is not valid. Reason: Unrecognized match type nosuchop\n at [Source: "
        f"(String)\"{bad_json}\"; line: 1, column: {bad_json.index('[1]') + 2}]",
    )
    assert err == expected, (
        f"CreateArchive with EventPattern {bad_pattern!r} settled on {err!r}, expected "
        f"{expected!r}. The response that came back instead was {unexpected!r}"
    )

    # Effect absent, both directions.
    listed = _list_archive_names(events, bus_arn)
    assert rejected_name not in listed, (
        f"the refused CreateArchive still created archive {rejected_name!r}: ListArchives over "
        f"{bus_arn} returned {listed!r}"
    )
    gone, still = _error(lambda: events.describe_archive(ArchiveName=rejected_name))
    assert gone == ("ResourceNotFoundException", f"Archive {rejected_name} does not exist."), (
        f"DescribeArchive on the refused archive {rejected_name!r} settled on {gone!r}, expected "
        f"'ResourceNotFoundException'; the response was {still!r}"
    )

    # Positive control, same file: the corrected form of the SAME pattern creates an archive that
    # reaches ENABLED and really ingests a matching event.
    good_name = _xname(ctx, "arc-ok")
    good_pattern = {"source": [source], "detail": {"n": [{"numeric": [">", 0]}]}}
    events.create_archive(
        ArchiveName=good_name,
        EventSourceArn=bus_arn,
        EventPattern=json.dumps(good_pattern),
    )
    ctx.on_cleanup(lambda: _delete_archive_and_wait(ctx, good_name))
    enabled = _poll_until(
        lambda: events.describe_archive(ArchiveName=good_name),
        lambda d: d.get("State") in ("ENABLED", "CREATE_FAILED", "DISABLED"),
        timeout_s=300.0,
        interval_s=3.0,
        description=f"control archive {good_name} left CREATING",
    )
    assert enabled["State"] == "ENABLED", (
        f"the control archive settled at State={enabled['State']!r}, expected 'ENABLED': "
        f"{enabled!r}"
    )
    assert good_name in _list_archive_names(events, bus_arn), (
        f"the control archive {good_name!r} is absent from ListArchives over {bus_arn}, so the "
        f"membership assertion above cannot distinguish a refused create from a broken list"
    )

    resp = events.put_events(
        Entries=[
            {
                "Source": source,
                "DetailType": "Archived",
                "Detail": json.dumps({"n": 7}),
                "EventBusName": bus,
            }
        ]
    )
    assert resp.get("FailedEntryCount") == 0 and resp["Entries"][0].get("EventId"), (
        f"the control event was not published, so the ingest assertion below would be vacuous: "
        f"{resp!r}"
    )
    # Archive ingest lags PutEvents by minutes; there is nothing faster to poll.
    ingested = _poll_until(
        lambda: events.describe_archive(ArchiveName=good_name),
        lambda d: d.get("EventCount", 0) >= 1,
        timeout_s=900.0,
        interval_s=5.0,
        description=(
            f"control archive {good_name} ingested the matching event (real AWS took 151-353 s when "
            f"this check was written)"
        ),
    )
    assert ingested["EventCount"] == 1, (
        f"the control archive stored {ingested['EventCount']!r} events for 1 published: "
        f"{ingested!r}"
    )
    assert ingested.get("SizeBytes", 0) > 0, (
        f"the control archive counted the event but reports SizeBytes="
        f"{ingested.get('SizeBytes')!r}: the count is bookkeeping, nothing was stored, and the "
        f"'valid pattern works' half of this negative would be satisfied by an inert record"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>.

    ArchiveName is capped at 48 characters by real AWS, so archive kinds stay short."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _error(fn):
    """Return ((error code, message), None) for a call that fails, and a sentinel that cannot be
    mistaken for an error plus the response when the call unexpectedly SUCCEEDS.

    Returning a falsy sentinel on success would turn the strongest possible signal -- an emulator
    accepting input real AWS refuses -- into something that reads like a naming difference."""
    try:
        resp = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return (error.get("Code"), error.get("Message")), None
    return ("<call unexpectedly SUCCEEDED>", None), resp


def _list_archive_names(events, bus_arn: str) -> list[str]:
    """Every archive name on `bus_arn`, following NextToken by hand.

    ListArchives has no botocore paginator, and other archives can push ours off page one."""
    names: list[str] = []
    token: str | None = None
    while True:
        kwargs: dict[str, Any] = {"EventSourceArn": bus_arn}
        if token:
            kwargs["NextToken"] = token
        page = events.list_archives(**kwargs)
        names.extend(a["ArchiveName"] for a in page.get("Archives", []))
        token = page.get("NextToken")
        if not token:
            return names


def _delete_archive_and_wait(ctx, name: str, *, timeout_s: float = 180.0) -> None:
    """Delete an archive and wait for it to be gone: the event bus cannot be deleted while an
    archive still references it."""
    events = ctx.client("events")
    try:
        events.delete_archive(ArchiveName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise RuntimeError(f"could not delete archive {name}: {exc}") from exc
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            events.describe_archive(ArchiveName=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
        time.sleep(3)
    raise RuntimeError(f"archive {name} still present {timeout_s}s after DeleteArchive; its event bus "
                       f"may fail to delete")


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
