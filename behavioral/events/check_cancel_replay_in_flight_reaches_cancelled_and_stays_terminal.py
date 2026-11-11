"""cancel-replay-in-flight-reaches-cancelled-and-stays-terminal."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-replay-in-flight-reaches-cancelled-and-stays-terminal"
GROUP = "replay"
SERVICES = ["events"]

_ARCHIVE_TIMEOUT_S = 90.0
_REPLAY_TIMEOUT_S = 240.0
_TERMINAL = ("CANCELLED", "COMPLETED", "FAILED")
_CANCEL_ATTEMPTS = 3


@tags("axis:happy-path", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CancelReplay on a just-started replay answers CANCELLING and it settles CANCELLED with a
    ReplayEndTime, as ListReplays agrees; it cannot be cancelled again and its name stays taken."""
    events = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    bus_arn = events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    archive = ctx.unique_name("sim2real-behav-arch-")
    archive_arn = events.create_archive(ArchiveName=archive, EventSourceArn=bus_arn)["ArchiveArn"]
    ctx.on_cleanup(lambda: events.delete_archive(ArchiveName=archive))
    state = _poll(lambda: events.describe_archive(ArchiveName=archive)["State"],
                  lambda s: s in ("ENABLED", "CREATE_FAILED"), _ARCHIVE_TIMEOUT_S, "archive settles", ctx)
    assert state == "ENABLED", f"archive must be ENABLED before replaying, got {state!r}"

    now = datetime.datetime.now(datetime.timezone.utc)
    window = {"EventStartTime": now - datetime.timedelta(hours=1), "EventEndTime": now}
    # A replay over an empty window may finish before CancelReplay arrives, and CancelReplay on a
    # finished replay is refused; only a replay still in flight is graded, so a fresh one is
    # started until the cancel lands while it is live.
    for attempt in range(1, _CANCEL_ATTEMPTS + 1):
        replay = ctx.unique_name("sim2real-behav-rp-")
        started = events.start_replay(
            ReplayName=replay, EventSourceArn=archive_arn, Destination={"Arn": bus_arn}, **window
        )
        ctx.on_cleanup(lambda name=replay: _cancel_if_live(events, name))
        assert started["ReplayArn"].endswith(f":replay/{replay}"), (
            f"StartReplay returned ReplayArn {started['ReplayArn']!r}, expected one ending in :replay/{replay}"
        )
        try:
            cancelled = events.cancel_replay(ReplayName=replay)
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            refused_as_finished = (
                err.get("Code") == "IllegalStatusException"
                and err.get("Message") == f"Replay {replay} is not in a valid state for this operation."
                and events.describe_replay(ReplayName=replay)["State"] == "COMPLETED"
            )
            if not refused_as_finished or attempt == _CANCEL_ATTEMPTS:
                raise AssertionError(
                    f"CancelReplay on a just-started replay must answer CANCELLING; attempt {attempt} "
                    f"was refused with {err.get('Code')!r} {err.get('Message')!r}"
                ) from exc
    assert cancelled["State"] == "CANCELLING", (
        f"CancelReplay on a just-started replay must answer CANCELLING, got {cancelled.get('State')!r}"
    )
    assert cancelled["ReplayArn"] == started["ReplayArn"], (
        "CancelReplay must name the same replay ARN StartReplay returned"
    )

    # Cancellation is asynchronous: only the terminal state shows the cancel was not dropped.
    final = _poll(lambda: events.describe_replay(ReplayName=replay),
                  lambda d: d["State"] in _TERMINAL, _REPLAY_TIMEOUT_S, "replay reaches a terminal state",
                  ctx)
    assert final["State"] == "CANCELLED", (
        f"a cancelled replay must end CANCELLED, got {final['State']!r} ({final.get('StateReason')!r})"
    )
    assert final.get("ReplayEndTime") is not None, f"a CANCELLED replay must carry ReplayEndTime: {final!r}"
    assert final["EventSourceArn"] == archive_arn and final["Destination"]["Arn"] == bus_arn, (
        "cancelling must not alter the replay's source or destination"
    )

    listed = _list_replay_states(events, replay)
    assert listed == {replay: "CANCELLED"}, f"ListReplays(NamePrefix=...) must agree on CANCELLED, got {listed!r}"

    code, message = _error(lambda: events.cancel_replay(ReplayName=replay))
    assert (code, message) == (
        "IllegalStatusException", f"Replay {replay} is not in a valid state for this operation."
    ), f"cancelling a CANCELLED replay must be refused, got {code!r} {message!r}"

    code, message = _error(lambda: events.start_replay(
        ReplayName=replay, EventSourceArn=archive_arn, Destination={"Arn": bus_arn}, **window
    ))
    assert (code, message) == ("ResourceAlreadyExistsException", f"Replay {replay} already exists."), (
        f"a cancelled replay's name stays taken; StartReplay under it gave {code!r} {message!r}"
    )
    assert events.describe_replay(ReplayName=replay)["State"] == "CANCELLED", (
        "the refused StartReplay must leave the cancelled replay untouched"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(read, done, timeout_s: float, what: str, ctx):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = read()
        if done(value):
            return value
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"{what}: the run budget ended first; not graded")
    raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last read {value!r}")


def _list_replay_states(events, prefix: str) -> dict:
    states, token = {}, None
    while True:
        kwargs = {"NamePrefix": prefix}
        if token:
            kwargs["NextToken"] = token
        resp = events.list_replays(**kwargs)
        states.update({r["ReplayName"]: r["State"] for r in resp.get("Replays", [])})
        token = resp.get("NextToken")
        if not token:
            return states


def _cancel_if_live(events, name: str) -> None:
    """Teardown: a replay still STARTING or RUNNING is cancelled so it does not outlive the run."""
    if events.describe_replay(ReplayName=name)["State"] in ("STARTING", "RUNNING"):
        events.cancel_replay(ReplayName=name)


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
