"""replay-completion-populates-timestamps-and-list-state-filter-discriminates."""
from __future__ import annotations

import datetime
import json
import time

from behavioral_harness import tags

CHECK = "replay-completion-populates-timestamps-and-list-state-filter-discriminates"
GROUP = 'replay'
SERVICES = ['events']


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A COMPLETED replay exposes ReplayStartTime, ReplayEndTime and EventLastReplayedTime on
    DescribeReplay, and paging ListReplays(State=COMPLETED) finds the replay with every listed
    entry COMPLETED.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_ListReplays.html
    """
    ev = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    bus_resp = ev.create_event_bus(Name=bus, Tags=[{"Key": "sim2real:managed", "Value": "true"}])
    ctx.on_cleanup(lambda n=bus: ev.delete_event_bus(Name=n))
    bus_arn = bus_resp["EventBusArn"]

    archive_name = ctx.unique_name("sim2real-behav-archive-")
    ev.create_archive(ArchiveName=archive_name, EventSourceArn=bus_arn)
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
    assert archive["State"] == "ENABLED", f"archive did not enable: {archive!r}"

    before_publish = datetime.datetime.now(datetime.timezone.utc)
    marker_detail = json.dumps({"marker": ctx.unique_name("m-")})
    put_resp = ev.put_events(Entries=[{
        "EventBusName": bus, "Source": "sim2real.replay-timestamps",
        "DetailType": "sim2real-marker", "Detail": marker_detail,
    }])
    assert put_resp.get("FailedEntryCount", 0) == 0, f"marker event rejected: {put_resp!r}"

    # Archival is itself async: a replay over a window with nothing archived in it completes
    # instantly with no EventLastReplayedTime, so wait for EventCount to actually move before
    # computing the replay's EventEndTime. EventCount lags well past the archive's own ENABLED
    # transition (50-320 s), so this is the long pole of the check.
    _deadline = time.monotonic() + 480
    archive = None
    while time.monotonic() < _deadline:
        archive = ev.describe_archive(ArchiveName=archive_name)
        if archive.get("EventCount", 0) > 0:
            break
        time.sleep(5)
    else:
        raise AssertionError(f"archive never ingested the marker event within 480s: {archive!r}")
    now = datetime.datetime.now(datetime.timezone.utc)
    replay_name = ctx.unique_name("sim2real-behav-replay-")
    ev.start_replay(
        ReplayName=replay_name,
        EventSourceArn=archive["ArchiveArn"],
        EventStartTime=before_publish - datetime.timedelta(minutes=1),
        EventEndTime=now,
        Destination={"Arn": bus_arn},
    )

    _deadline = time.monotonic() + 300
    desc = None
    while time.monotonic() < _deadline:
        desc = ev.describe_replay(ReplayName=replay_name)
        if desc["State"] in ("COMPLETED", "FAILED", "CANCELLED"):
            break
        time.sleep(5)
    else:
        raise AssertionError(f"replay did not settle within 300s: {desc!r}")
    assert desc["State"] == "COMPLETED", f"expected COMPLETED, got {desc['State']!r} ({desc.get('StateReason')!r})"

    for field in ("ReplayStartTime", "ReplayEndTime", "EventLastReplayedTime"):
        assert field in desc and desc[field] is not None, (
            f"a COMPLETED replay must populate {field}, got DescribeReplay={desc!r}"
        )
    assert desc["ReplayEndTime"] >= desc["ReplayStartTime"], (
        f"ReplayEndTime {desc['ReplayEndTime']!r} must not precede ReplayStartTime {desc['ReplayStartTime']!r}"
    )

    # ListReplays rejects State combined with NamePrefix ("At most one filter is allowed"),
    # though the model declares both optional, so find the replay by a bounded page walk.
    seen_names: set[str] = set()
    seen_states: set[str] = set()
    token = None
    for _ in range(200):
        kwargs = {"State": "COMPLETED", "Limit": 100}
        if token:
            kwargs["NextToken"] = token
        page = ev.list_replays(**kwargs)
        for r in page.get("Replays", []):
            seen_names.add(r["ReplayName"])
            seen_states.add(r["State"])
        if replay_name in seen_names:
            break
        token = page.get("NextToken")
        if not token:
            break
    assert seen_states <= {"COMPLETED"}, (
        f"every entry ListReplays(State='COMPLETED') returns must itself be COMPLETED, saw states "
        f"{seen_states!r}"
    )
    assert replay_name in seen_names, (
        f"ListReplays(State='COMPLETED') never turned up {replay_name!r} across "
        f"{len(seen_names)} replay(s) paged"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
