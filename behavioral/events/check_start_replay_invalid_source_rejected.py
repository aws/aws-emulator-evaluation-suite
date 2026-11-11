"""start-replay-invalid-source-rejected."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-replay-invalid-source-rejected"
GROUP = 'replay'
SERVICES = ['events']

def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _best_effort_cancel(events_client, replay_name):
    try:
        state = events_client.describe_replay(ReplayName=replay_name)["State"]
        if state in ("STARTING", "RUNNING"):
            events_client.cancel_replay(ReplayName=replay_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartReplay referencing an archive ARN that does not exist is rejected: real EventBridge validates the source ARN and returns ValidationException rather than starting a replay that silently produces nothing. A positive control on a genuinely existing archive proves the account and credentials are otherwise healthy for StartReplay, so the rejection is specific to the bogus source and not a blanket refusal."""
    ev = ctx.client("events")
    bus_name = ctx.unique_name("sim2real-behav-bus-")
    bus_arn = ev.create_event_bus(Name=bus_name)["EventBusArn"]
    ctx.on_cleanup(lambda: ev.delete_event_bus(Name=bus_name))

    archive_name = ctx.unique_name("sim2real-behav-archive-")
    archive_arn = ev.create_archive(ArchiveName=archive_name, EventSourceArn=bus_arn)["ArchiveArn"]
    ctx.on_cleanup(lambda: ev.delete_archive(ArchiveName=archive_name))

    deadline = time.monotonic() + 60
    desc = None
    while time.monotonic() < deadline:
        desc = ev.describe_archive(ArchiveName=archive_name)
        if desc["State"] in ("ENABLED", "CREATE_FAILED"):
            break
        time.sleep(1)
    else:
        raise AssertionError(f"archive did not settle within 60s: {desc!r}")
    assert desc["State"] == "ENABLED", f"archive did not enable: {desc}"

    now = datetime.datetime.now(datetime.timezone.utc)

    # Positive control: StartReplay against the real (existing) archive succeeds, so the
    # rejection below can be attributed to the bogus source, not a blanket refusal.
    control_replay_name = ctx.unique_name("sim2real-behav-replay-ctrl-")
    control = ev.start_replay(
        ReplayName=control_replay_name,
        EventSourceArn=archive_arn,
        EventStartTime=now - datetime.timedelta(hours=1),
        EventEndTime=now,
        Destination={"Arn": bus_arn},
    )
    assert control["State"] in ("STARTING", "RUNNING", "COMPLETED"), (
        f"StartReplay against a real archive must succeed, got {control.get('State')}"
    )
    ctx.on_cleanup(lambda: _best_effort_cancel(ev, control_replay_name))

    # Break exactly one thing: an archive ARN that does not exist.
    bogus_archive_arn = archive_arn + "-does-not-exist"
    replay_name = ctx.unique_name("sim2real-behav-replay-")

    err = _client_error(
        lambda: ev.start_replay(
            ReplayName=replay_name,
            EventSourceArn=bogus_archive_arn,
            EventStartTime=now - datetime.timedelta(hours=1),
            EventEndTime=now,
            Destination={"Arn": bus_arn},
        )
    )
    assert err.get("Code") == "ValidationException", f"expected ValidationException, got {err}"
    expected_message = (
        f"Parameter EventSourceArn is not valid. Reason: Archive {archive_name}-does-not-exist "
        f"does not exist."
    )
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    listed = ev.list_replays(NamePrefix=replay_name)["Replays"]
    assert listed == [], f"rejected StartReplay must not create a replay: {listed}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
