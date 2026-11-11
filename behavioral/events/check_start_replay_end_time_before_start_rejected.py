"""start-replay-end-time-before-start-rejected."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-replay-end-time-before-start-rejected"
GROUP = 'replay'
SERVICES = ['events']

def _client_error(fn):
    """Call fn() and return its botocore Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _best_effort_cancel(ev, replay_name):
    try:
        state = ev.describe_replay(ReplayName=replay_name)["State"]
        if state in ("STARTING", "RUNNING"):
            ev.cancel_replay(ReplayName=replay_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartReplay with EventEndTime before EventStartTime is rejected with ValidationException and
    creates no replay; a valid-window replay on the same archive starts first as a control."""
    ev = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    bus_resp = ev.create_event_bus(Name=bus)
    ctx.on_cleanup(lambda n=bus: ev.delete_event_bus(Name=n))
    default_bus_arn = bus_resp["EventBusArn"]

    archive_name = ctx.unique_name("sim2real-behav-archive-")
    ev.create_archive(ArchiveName=archive_name, EventSourceArn=default_bus_arn)
    ctx.on_cleanup(lambda a=archive_name: ev.delete_archive(ArchiveName=a))

    _deadline = time.monotonic() + 60
    desc = None
    while time.monotonic() < _deadline:
        desc = ev.describe_archive(ArchiveName=archive_name)
        if desc["State"] in ("ENABLED", "CREATE_FAILED"):
            break
        time.sleep(1)
    else:
        raise AssertionError(f"archive did not settle within 60s: {desc!r}")
    assert desc["State"] == "ENABLED", f"archive did not enable: {desc}"

    now = datetime.datetime.now(datetime.timezone.utc)
    earlier = now - datetime.timedelta(hours=1)

    # Positive control: the same call shape, a valid (start < end) window, on the same archive.
    control_name = ctx.unique_name("sim2real-behav-replay-ctl-")
    control_resp = ev.start_replay(
        ReplayName=control_name,
        EventSourceArn=desc["ArchiveArn"],
        EventStartTime=earlier,
        EventEndTime=now,
        Destination={"Arn": default_bus_arn},
    )
    ctx.on_cleanup(lambda n=control_name: _best_effort_cancel(ev, n))
    assert control_resp["State"] in ("STARTING", "RUNNING", "COMPLETED"), (
        f"the positive control (a valid time window) did not start, got {control_resp!r}"
    )

    replay_name = ctx.unique_name("sim2real-behav-replay-")

    error = _client_error(
        lambda: ev.start_replay(
            ReplayName=replay_name,
            EventSourceArn=desc["ArchiveArn"],
            EventStartTime=now,       # start AFTER end -> invalid range
            EventEndTime=earlier,
            Destination={"Arn": default_bus_arn},
        )
    )
    assert error.get("Code") == "ValidationException", (
        f"StartReplay with EventEndTime before EventStartTime was rejected with "
        f"{error.get('Code')!r}, expected \"ValidationException\""
    )
    expected_message = (
        "Parameter EventEndTime is not valid. Reason: EventStartTime must be before EventEndTime."
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    list_resp = ev.list_replays(NamePrefix=replay_name)["Replays"]
    assert list_resp == [], f"an invalid StartReplay call must not create a Replay resource: {list_resp!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
