"""describe-replay-nonexistent-not-found."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-replay-nonexistent-not-found"
GROUP = 'replay'
SERVICES = ['events']

_LIVE_STATES = ("STARTING", "RUNNING", "COMPLETED")


def _error(fn):
    """(code, message) of a call that must fail; a call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeReplay for a never-started replay name raises ResourceNotFoundException and
    ListReplays omits it; a control replay succeeds, and starting a replay under the probed
    name afterwards makes the identical DescribeReplay call succeed."""
    ev = ctx.client("events")

    bus_name = ctx.unique_name("sim2real-behav-bus-")
    bus_arn = ev.create_event_bus(Name=bus_name)["EventBusArn"]
    ctx.on_cleanup(lambda: ev.delete_event_bus(Name=bus_name))

    archive_name = ctx.unique_name("sim2real-behav-archive-")
    archive_arn = ev.create_archive(ArchiveName=archive_name, EventSourceArn=bus_arn)["ArchiveArn"]
    ctx.on_cleanup(lambda: ev.delete_archive(ArchiveName=archive_name))
    _poll_archive_settled(ev, archive_name)

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=10)
    window_end = now

    # Positive control: DescribeReplay on a real, just-started replay must succeed -- without
    # this, the not-found assertion below cannot tell "correctly reports absence" from
    # "DescribeReplay rejects every call regardless of the name".
    control_name = ctx.unique_name("sim2real-behav-replay-ctl-")
    ev.start_replay(
        ReplayName=control_name,
        EventSourceArn=archive_arn,
        EventStartTime=window_start,
        EventEndTime=window_end,
        Destination={"Arn": bus_arn},
    )
    ctx.on_cleanup(lambda: _best_effort_cancel(ev, control_name))
    control_desc = _poll_replay_state(ev, control_name, _LIVE_STATES)
    assert control_desc["State"] in _LIVE_STATES, (
        f"control replay against a real archive did not reach a live state, so the refusal below "
        f"would be indistinguishable from DescribeReplay rejecting everything: {control_desc}"
    )

    # The probe: a name that was never passed to StartReplay.
    probe_name = ctx.unique_name("sim2real-behav-replay-")
    err = _error(lambda: ev.describe_replay(ReplayName=probe_name))
    assert err == ("ResourceNotFoundException", f"Replay {probe_name} does not exist."), (
        f"expected ResourceNotFoundException, got {err!r}"
    )

    # Effect absent via an independent read: the probed name never shows up in ListReplays either.
    listed = {r["ReplayName"] for r in ev.list_replays(NamePrefix=probe_name).get("Replays", [])}
    assert probe_name not in listed, (
        f"describe_replay reported {probe_name!r} not-found but list_replays shows it: {listed}"
    )

    # Restore: start a replay under the EXACT probed name. The identical DescribeReplay call
    # must now succeed, proving the earlier refusal was specifically about that name never having
    # existed, not some other rejection.
    ev.start_replay(
        ReplayName=probe_name,
        EventSourceArn=archive_arn,
        EventStartTime=window_start,
        EventEndTime=window_end,
        Destination={"Arn": bus_arn},
    )
    ctx.on_cleanup(lambda: _best_effort_cancel(ev, probe_name))
    restored_desc = _poll_replay_state(ev, probe_name, _LIVE_STATES)
    assert restored_desc["State"] in _LIVE_STATES, (
        f"identical DescribeReplay(ReplayName={probe_name!r}) should succeed once that name is "
        f"actually started, got {restored_desc}"
    )



def _poll_archive_settled(ev, archive_name: str, timeout_s: float = 60.0):
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = ev.describe_archive(ArchiveName=archive_name)
        if desc["State"] in ("ENABLED", "CREATE_FAILED"):
            if desc["State"] != "ENABLED":
                raise AssertionError(f"archive {archive_name} failed to create: {desc}")
            return desc
        time.sleep(1)
    raise AssertionError(f"archive {archive_name} did not settle within {timeout_s}s: {desc}")


def _poll_replay_state(ev, replay_name: str, terminal_states, timeout_s: float = 30.0):
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = ev.describe_replay(ReplayName=replay_name)
        if desc["State"] in terminal_states or desc["State"] in ("FAILED", "CANCELLED"):
            return desc
        time.sleep(2)
    raise AssertionError(f"replay {replay_name} did not reach a live state within {timeout_s}s: {desc}")


def _best_effort_cancel(ev, replay_name: str) -> None:
    try:
        state = ev.describe_replay(ReplayName=replay_name)["State"]
        if state in ("STARTING", "RUNNING"):
            ev.cancel_replay(ReplayName=replay_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
