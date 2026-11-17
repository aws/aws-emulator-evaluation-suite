"""cancel-replay-on-a-name-never-created-is-rejected."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-replay-on-a-name-never-created-is-rejected"
GROUP = "replay"
SERVICES = ["events"]

_ARCHIVE_TIMEOUT_S = 90.0
_REPLAY_TIMEOUT_S = 240.0
_START_ATTEMPTS = 3


def _error(fn) -> tuple[str, str]:
    """(code, message) of a call that must fail; an unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll(read, done, timeout_s: float, what: str):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = read()
        if done(value):
            return value
        time.sleep(2)
    raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last read {value!r}")


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelReplay on a name that was never created is refused as not-found, leaving a replay
    actually in flight untouched, and the same call against that replay cancels it."""
    events = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    bus_arn = events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    archive = ctx.unique_name("sim2real-behav-arch-")
    archive_arn = events.create_archive(ArchiveName=archive, EventSourceArn=bus_arn)["ArchiveArn"]
    ctx.on_cleanup(lambda: events.delete_archive(ArchiveName=archive))
    state = _poll(lambda: events.describe_archive(ArchiveName=archive)["State"],
                 lambda s: s in ("ENABLED", "CREATE_FAILED"), _ARCHIVE_TIMEOUT_S, "the archive settles")
    assert state == "ENABLED", f"the archive must be ENABLED before replaying, got {state!r}"

    now = datetime.datetime.now(datetime.timezone.utc)
    window = {"EventStartTime": now - datetime.timedelta(hours=1), "EventEndTime": now}

    missing = ctx.unique_name("sim2real-behav-rp-")
    code, message = _error(lambda: events.cancel_replay(ReplayName=missing))
    assert (code, message) == (
        "ResourceNotFoundException", f"Replay {missing} does not exist.",
    ), f"cancelling a replay name that was never created must be not-found, got {code!r} {message!r}"

    # An empty-window replay can finish before the cancel lands, and CancelReplay on a replay
    # that already finished is refused as IllegalStatusException rather than cancelled; retry
    # with a fresh replay name until one is caught while still in flight.
    cancelled = None
    for attempt in range(1, _START_ATTEMPTS + 1):
        replay = ctx.unique_name("sim2real-behav-rp-")
        started = events.start_replay(
            ReplayName=replay, EventSourceArn=archive_arn, Destination={"Arn": bus_arn}, **window
        )
        ctx.on_cleanup(lambda name=replay: _cancel_if_live(events, name))
        try:
            cancelled = events.cancel_replay(ReplayName=replay)
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            finished_first = (
                err.get("Code") == "IllegalStatusException"
                and events.describe_replay(ReplayName=replay)["State"] == "COMPLETED"
            )
            if not finished_first or attempt == _START_ATTEMPTS:
                raise AssertionError(
                    f"cancelling a just-started replay must succeed; attempt {attempt} was "
                    f"refused with {err.get('Code')!r} {err.get('Message')!r}"
                ) from exc
    assert cancelled["ReplayArn"] == started["ReplayArn"], (
        "CancelReplay must name the same replay ARN StartReplay returned"
    )

    final = _poll(lambda: events.describe_replay(ReplayName=replay),
                  lambda d: d["State"] in ("CANCELLED", "COMPLETED", "FAILED"), _REPLAY_TIMEOUT_S,
                  "the replay reaches a terminal state")
    assert final["State"] == "CANCELLED", (
        f"a cancelled replay must end CANCELLED, got {final['State']!r} ({final.get('StateReason')!r})"
    )
    assert final.get("ReplayEndTime") is not None, f"a CANCELLED replay must carry ReplayEndTime: {final!r}"


def _cancel_if_live(events, name: str) -> None:
    """Teardown: a replay still STARTING or RUNNING is cancelled so it does not outlive the run."""
    try:
        if events.describe_replay(ReplayName=name)["State"] in ("STARTING", "RUNNING"):
            events.cancel_replay(ReplayName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
