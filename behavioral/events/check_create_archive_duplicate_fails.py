"""create-archive-duplicate-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-archive-duplicate-fails"
GROUP = 'archive'
SERVICES = ['events']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateArchive with an existing ArchiveName is rejected with ResourceAlreadyExistsException,
    leaves the existing archive's Description untouched, and succeeds under a fresh name."""
    ev = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    bus_resp = ev.create_event_bus(Name=bus, Tags=_tags())
    ctx.on_cleanup(lambda n=bus: ev.delete_event_bus(Name=n))

    archive_name = ctx.unique_name("sim2real-behav-archive-")
    ev.create_archive(
        ArchiveName=archive_name,
        EventSourceArn=bus_resp['EventBusArn'],
        Description="original",
    )
    ctx.on_cleanup(lambda a=archive_name: ev.delete_archive(ArchiveName=a))
    _await_archive_enabled(ev, archive_name)

    err = _error(lambda: ev.create_archive(
        ArchiveName=archive_name,
        EventSourceArn=bus_resp['EventBusArn'],
        Description="duplicate-attempt-should-not-apply",
    ))
    expected = ("ResourceAlreadyExistsException", f"Archive {archive_name} already exists.")
    assert err == expected, (
        f"expected duplicate CreateArchive to fail with {expected}, got {err}"
    )

    # Effect-absence: the rejected duplicate request must not have mutated the existing archive.
    after = ev.describe_archive(ArchiveName=archive_name)
    assert after["Description"] == "original", (
        f"rejected duplicate CreateArchive mutated the existing archive's Description, got "
        f"{after['Description']!r}"
    )

    # Positive control: the identical shape of request succeeds with a fresh, non-conflicting name.
    control_name = ctx.unique_name("sim2real-behav-archive-ctrl-")
    ev.create_archive(
        ArchiveName=control_name,
        EventSourceArn=bus_resp['EventBusArn'],
        Description="control",
    )
    ctx.on_cleanup(lambda a=control_name: ev.delete_archive(ArchiveName=a))
    control_after = _await_archive_enabled(ev, control_name)
    assert control_after["Description"] == "control", (
        f"control CreateArchive with a fresh name did not apply, got "
        f"{control_after['Description']!r}"
    )


def _error(fn):
    """Call fn() and return its (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _await_archive_enabled(ev, archive_name, timeout_s=30):
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = ev.describe_archive(ArchiveName=archive_name)
        if desc["State"] in ("ENABLED", "CREATE_FAILED"):
            break
        time.sleep(1)
    else:
        raise AssertionError(f"archive {archive_name} did not settle within {timeout_s}s: {desc!r}")
    assert desc["State"] == "ENABLED", f"archive {archive_name} did not become ENABLED: {desc!r}"
    return desc


def _tags():
    return [{"Key": "sim2real:managed", "Value": "true"}]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
