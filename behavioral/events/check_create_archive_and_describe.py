"""create-archive-and-describe."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-archive-and-describe"
GROUP = 'archive'
SERVICES = ['events']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateArchive transitions to ENABLED and is reflected in DescribeArchive."""
    ev = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    bus_resp = ev.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": "behav"}])
    ctx.on_cleanup(lambda n=bus: ev.delete_event_bus(Name=n))
    archive_name = ctx.unique_name("sim2real-behav-archive-")
    ev.create_archive(ArchiveName=archive_name, EventSourceArn=bus_resp['EventBusArn'])
    ctx.on_cleanup(lambda a=archive_name: ev.delete_archive(ArchiveName=a))
    _deadline = time.monotonic() + 30
    d = None
    while time.monotonic() < _deadline:
        d = ev.describe_archive(ArchiveName=archive_name)
        if d['State'] in ('ENABLED', 'CREATE_FAILED'):
            break
        time.sleep(1)
    else:
        raise AssertionError(f"poll condition not met within {30}s: {d!r}")
    desc = d
    assert desc["State"] == "ENABLED", f"archive did not become ENABLED: {desc}"
    assert desc["ArchiveName"] == archive_name, (
        f"DescribeArchive returned a different name: expected {archive_name!r}, got {desc.get('ArchiveName')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
