"""replay-reaches-completed."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replay-reaches-completed"
GROUP = 'replay'
SERVICES = ['events']

def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartReplay over an empty time window transitions the replay through STARTING/RUNNING to COMPLETED, and CancelReplay on a COMPLETED replay is rejected with IllegalStatusException (terminal state is immutable)."""
    ev = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    bus_resp = ev.create_event_bus(Name=bus, Tags=[{"Key": "sim2real:managed", "Value": "true"}])
    ctx.on_cleanup(lambda n=bus: ev.delete_event_bus(Name=n))
    default_bus_arn = bus_resp["EventBusArn"]

    archive_name = ctx.unique_name("sim2real-behav-archive-")
    ev.create_archive(ArchiveName=archive_name, EventSourceArn=default_bus_arn)
    ctx.on_cleanup(lambda a=archive_name: ev.delete_archive(ArchiveName=a))

    _deadline = time.monotonic() + 60
    archive = None
    while time.monotonic() < _deadline:
        archive = ev.describe_archive(ArchiveName=archive_name)
        if archive["State"] in ("ENABLED", "CREATE_FAILED"):
            break
        time.sleep(1)
    else:
        raise AssertionError(f"archive did not settle within 60s: {archive!r}")
    assert archive["State"] == "ENABLED", f"archive did not enable: {archive}"

    now = datetime.datetime.now(datetime.timezone.utc)
    replay_name = ctx.unique_name("sim2real-behav-replay-")
    start = ev.start_replay(
        ReplayName=replay_name,
        EventSourceArn=archive["ArchiveArn"],
        EventStartTime=now - datetime.timedelta(minutes=10),
        EventEndTime=now,
        Destination={"Arn": default_bus_arn},
    )
    assert start["State"] in ("STARTING", "RUNNING", "COMPLETED"), f"unexpected initial state: {start}"
    assert start["ReplayArn"].endswith(replay_name)

    _deadline = time.monotonic() + 300
    desc = None
    while time.monotonic() < _deadline:
        desc = ev.describe_replay(ReplayName=replay_name)
        if desc["State"] in ("COMPLETED", "FAILED", "CANCELLED"):
            break
        time.sleep(5)
    else:
        raise AssertionError(f"replay did not settle within 300s: {desc!r}")
    assert desc["State"] == "COMPLETED", f"expected COMPLETED, got {desc['State']} ({desc.get('StateReason')})"
    assert desc["EventSourceArn"] == archive["ArchiveArn"]
    assert "ReplayEndTime" in desc, f"COMPLETED replay must expose ReplayEndTime: {desc}"

    listed = {r["ReplayName"] for r in ev.list_replays(NamePrefix=replay_name)["Replays"]}
    assert replay_name in listed, f"completed replay must still be listable, got {listed}"

    err = _client_error(lambda: ev.cancel_replay(ReplayName=replay_name))
    assert err.get("Code") == "IllegalStatusException", (
        f"expected IllegalStatusException cancelling a COMPLETED replay, got {err}"
    )
    expected_message = f"Replay {replay_name} is not in a valid state for this operation."
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
