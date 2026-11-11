"""events-archive-replay-to-a-bus-other-than-the-archive-source-rejected."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-archive-replay-to-a-bus-other-than-the-archive-source-rejected"

GROUP = "archive-replay"

SERVICES = ["events"]


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "plane:control")
def run(ctx) -> None:
    """StartReplay into a bus other than the archive's source is refused with ValidationException
    and creates no replay; the same request aimed at the archive's own source bus is accepted.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_StartReplay.html
    """
    events = ctx.client("events")

    source_bus = ctx.unique_name("sim2real-arr-src-")
    source_arn = events.create_event_bus(Name=source_bus, Tags=_tags_kv())["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=source_bus))
    other_bus = ctx.unique_name("sim2real-arr-oth-")
    other_arn = events.create_event_bus(Name=other_bus, Tags=_tags_kv())["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=other_bus))

    archive = ctx.unique_name("sim2real-arr-arc-")
    archive_arn = events.create_archive(ArchiveName=archive, EventSourceArn=source_arn)["ArchiveArn"]
    ctx.on_cleanup(lambda: _delete_archive_and_wait(events, archive))
    _wait_archive_enabled(events, archive)

    now = datetime.now(timezone.utc)
    window = {"EventStartTime": now - timedelta(minutes=10), "EventEndTime": now - timedelta(minutes=1)}

    refused = ctx.unique_name("sim2real-arr-rp-bad-")
    err = _error(lambda: events.start_replay(
        ReplayName=refused, EventSourceArn=archive_arn, Destination={"Arn": other_arn}, **window
    ))
    # The Smithy model does not list ValidationException for StartReplay, but AWS returns it.
    expected = (
        "ValidationException",
        "Parameter Destination.Arn is not valid. Reason: Cross event bus replay is not permitted.",
    )
    assert err == expected, (
        f"StartReplay from an archive of {source_bus!r} into {other_bus!r} returned {err!r}, "
        f"expected {expected!r}"
    )
    absent = _error(lambda: events.describe_replay(ReplayName=refused))
    assert absent == ("ResourceNotFoundException", f"Replay {refused} does not exist."), (
        f"the refused replay {refused!r} is describable afterwards (DescribeReplay -> {absent!r}), "
        f"so the refusal still created it"
    )
    listed = _list_replay_names(events, refused)
    assert listed == [], f"the refused replay {refused!r} is listed: {listed!r}"

    # Positive control: the same request, differing only in the destination bus, is accepted.
    accepted = ctx.unique_name("sim2real-arr-rp-ok-")
    # No DeleteReplay API exists, so the accepted replay cannot be cleaned up.
    ok = events.start_replay(
        ReplayName=accepted, EventSourceArn=archive_arn, Destination={"Arn": source_arn}, **window
    )
    assert ok.get("ReplayArn", "").endswith(accepted), f"control StartReplay returned {ok!r}"
    desc = events.describe_replay(ReplayName=accepted)
    assert desc.get("Destination", {}).get("Arn") == source_arn, (
        f"control replay's Destination is {desc.get('Destination')!r}, expected {source_arn!r}"
    )
    assert desc.get("EventSourceArn") == archive_arn, (
        f"control replay's EventSourceArn is {desc.get('EventSourceArn')!r}, expected {archive_arn!r}"
    )


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real:managed", "Value": "true"}]


class _Accepted(Exception):
    """Raised when a call expected to fail succeeds, so it can never read as an error code."""


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code", "<no code>"), error.get("Message")
    raise _Accepted(f"call was expected to be refused but succeeded: {result!r}")


def _list_replay_names(events, prefix: str) -> list[str]:
    names: list[str] = []
    kwargs: dict[str, Any] = {"NamePrefix": prefix}
    while True:
        page = events.list_replays(**kwargs)
        names.extend(r["ReplayName"] for r in page.get("Replays", []))
        if not page.get("NextToken"):
            return names
        kwargs["NextToken"] = page["NextToken"]


def _wait_archive_enabled(events, name: str, *, timeout_s: float = 300.0) -> None:
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = events.describe_archive(ArchiveName=name).get("State")
        if state in ("ENABLED", "CREATE_FAILED", "DISABLED"):
            break
        time.sleep(3)
    assert state == "ENABLED", f"archive {name} settled at State={state!r}, expected 'ENABLED'"


def _delete_archive_and_wait(events, name: str, *, timeout_s: float = 180.0) -> None:
    """The bus cannot be deleted while an archive still references it, so wait for the delete."""
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
    raise RuntimeError(f"archive {name} still present {timeout_s}s after DeleteArchive")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
