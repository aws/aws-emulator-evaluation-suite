"""delete-archive-not-blocked-by-in-flight-replay-and-start-replay-on-it-refused."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-archive-not-blocked-by-in-flight-replay-and-start-replay-on-it-refused"
GROUP = "replay"
SERVICES = ["events"]

_ARCHIVE_SETTLE_TIMEOUT_S = 90.0


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteArchive succeeds while a replay from it is in flight (no dependency refusal), and a
    later StartReplay naming the deleted archive is a ValidationException naming the archive.
    """
    events = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    bus_arn = events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    archive = ctx.unique_name("sim2real-behav-arch-")
    archive_arn = events.create_archive(ArchiveName=archive, EventSourceArn=bus_arn)["ArchiveArn"]
    ctx.on_cleanup(lambda: _delete_archive_quietly(events, archive))
    state = _poll(
        lambda: events.describe_archive(ArchiveName=archive)["State"],
        lambda s: s in ("ENABLED", "CREATE_FAILED"),
        _ARCHIVE_SETTLE_TIMEOUT_S,
        "archive settles",
    )
    assert state == "ENABLED", f"archive must be ENABLED before replaying, got {state!r}"

    now = datetime.datetime.now(datetime.timezone.utc)
    replay = ctx.unique_name("sim2real-behav-rp-")
    started = events.start_replay(
        ReplayName=replay,
        EventSourceArn=archive_arn,
        Destination={"Arn": bus_arn},
        EventStartTime=now - datetime.timedelta(hours=1),
        EventEndTime=now,
    )
    ctx.on_cleanup(lambda: _cancel_if_live(events, replay))
    assert started["State"] in ("STARTING", "RUNNING"), (
        f"StartReplay must answer with a live, non-terminal state, got {started.get('State')!r}"
    )

    # Delete immediately after StartReplay's ack, while the replay is still reading the archive.
    events.delete_archive(ArchiveName=archive)
    archive_gone = _poll(
        lambda: _is_not_found(lambda: events.describe_archive(ArchiveName=archive)),
        lambda gone: gone,
        _ARCHIVE_SETTLE_TIMEOUT_S,
        "archive disappears after DeleteArchive",
    )
    assert archive_gone, (
        f"DeleteArchive({archive}) while its replay was in flight must still make the archive "
        f"disappear (DescribeArchive never reached ResourceNotFoundException)"
    )

    # A fresh replay name keeps the refusal about the archive, not about a name already in use.
    retry = ctx.unique_name("sim2real-behav-rp-")
    ctx.on_cleanup(lambda: _cancel_if_live(events, retry))
    code, message = _error(lambda: events.start_replay(
        ReplayName=retry,
        EventSourceArn=archive_arn,
        Destination={"Arn": bus_arn},
        EventStartTime=now - datetime.timedelta(hours=1),
        EventEndTime=now,
    ))
    assert code == "ValidationException", (
        f"StartReplay naming the now-deleted archive must be refused with ValidationException, "
        f"got {code!r} ({message!r})"
    )
    expected_message = f"Parameter EventSourceArn is not valid. Reason: Archive {archive} does not exist."
    assert message == expected_message, (
        f"expected the refusal message {expected_message!r}, got {message!r}"
    )


def _poll(read, done, timeout_s: float, what: str):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = read()
        if done(value):
            return value
        time.sleep(3)
    raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last read {value!r}")


def _cancel_if_live(events, name: str) -> None:
    """Cancel a replay still STARTING or RUNNING so it does not outlive the run."""
    try:
        if events.describe_replay(ReplayName=name)["State"] in ("STARTING", "RUNNING"):
            events.cancel_replay(ReplayName=name)
    except events.exceptions.ResourceNotFoundException:
        pass


def _delete_archive_quietly(events, name: str) -> None:
    try:
        events.delete_archive(ArchiveName=name)
    except events.exceptions.ResourceNotFoundException:
        pass


def _error(fn) -> tuple[str, str]:
    """(code, message) of a call that must fail; an unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _is_not_found(fn) -> bool:
    """A poll probe: True once fn() raises ResourceNotFoundException, False while it still
    succeeds or raises anything else."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException"
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
