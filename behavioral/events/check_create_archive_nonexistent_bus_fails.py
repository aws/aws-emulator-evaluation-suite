"""create-archive-nonexistent-bus-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-archive-nonexistent-bus-fails"
GROUP = 'archive'
SERVICES = ['events']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateArchive on a nonexistent bus fails ResourceNotFoundException and creates nothing; the
    identical call succeeds once that bus exists, and an archive on a real bus reaches ENABLED."""
    ev = ctx.client("events")

    control_bus_name = ctx.unique_name("sim2real-behav-bus-ctl-")
    control_bus_arn = ev.create_event_bus(Name=control_bus_name)["EventBusArn"]
    ctx.on_cleanup(lambda n=control_bus_name: ev.delete_event_bus(Name=n))
    control_archive_name = ctx.unique_name("sim2real-behav-archive-ctl-")
    ev.create_archive(ArchiveName=control_archive_name, EventSourceArn=control_bus_arn)
    ctx.on_cleanup(lambda a=control_archive_name: ev.delete_archive(ArchiveName=a))
    control_desc = _poll_archive_settled(ev, control_archive_name)
    assert control_desc["State"] == "ENABLED", (
        f"control archive against a real bus did not reach ENABLED, so the refusal below would "
        f"be indistinguishable from CreateArchive rejecting everything: {control_desc}"
    )

    account_id = control_bus_arn.split(":")[4]
    target_bus_name = ctx.unique_name("sim2real-behav-bus-tgt-")
    fake_bus_arn = f"arn:aws:events:{ctx.region}:{account_id}:event-bus/{target_bus_name}"
    archive_name = ctx.unique_name("sim2real-behav-archive-")

    err = _error(lambda: ev.create_archive(ArchiveName=archive_name, EventSourceArn=fake_bus_arn))
    expected = ("ResourceNotFoundException", f"Event bus {target_bus_name} does not exist.")
    assert err == expected, (
        f"CreateArchive against nonexistent bus {fake_bus_arn} expected {expected}, got {err}"
    )

    absent = _error(lambda: ev.describe_archive(ArchiveName=archive_name))
    expected_absent = ("ResourceNotFoundException", f"Archive {archive_name} does not exist.")
    assert absent == expected_absent, (
        f"the refused CreateArchive still left something DescribeArchive can see: independent "
        f"read of {archive_name} settled on {absent!r} instead of {expected_absent!r}"
    )

    ev.create_event_bus(Name=target_bus_name)
    ctx.on_cleanup(lambda n=target_bus_name: ev.delete_event_bus(Name=n))
    ev.create_archive(ArchiveName=archive_name, EventSourceArn=fake_bus_arn)
    ctx.on_cleanup(lambda a=archive_name: ev.delete_archive(ArchiveName=a))
    restored_desc = _poll_archive_settled(ev, archive_name)
    assert restored_desc["State"] == "ENABLED", (
        f"the identical CreateArchive call should succeed once {target_bus_name} exists, but the "
        f"archive settled at State={restored_desc['State']!r}: {restored_desc}"
    )


def _error(fn):
    """Call fn() and return its (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_archive_settled(ev, archive_name: str, timeout_s: float = 60.0):
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = ev.describe_archive(ArchiveName=archive_name)
        if desc["State"] in ("ENABLED", "CREATE_FAILED"):
            return desc
        time.sleep(1)
    raise AssertionError(f"archive {archive_name} did not settle within {timeout_s}s: {desc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
