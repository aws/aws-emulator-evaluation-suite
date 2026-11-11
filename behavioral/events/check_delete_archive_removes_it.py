"""delete-archive-removes-it."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-archive-removes-it"
GROUP = 'archive'
SERVICES = ['events']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteArchive removes the archive: an independent describe 404s, a mutation on the
    dead id also 404s, and the freed name is reusable by a fresh CreateArchive."""
    ev = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    bus_resp = ev.create_event_bus(Name=bus)
    ctx.on_cleanup(lambda n=bus: ev.delete_event_bus(Name=n))
    archive_name = ctx.unique_name("sim2real-behav-archive-")
    ev.create_archive(ArchiveName=archive_name, EventSourceArn=bus_resp['EventBusArn'])
    ctx.on_cleanup(lambda a=archive_name: ev.delete_archive(ArchiveName=a))
    ev.delete_archive(ArchiveName=archive_name)

    def _error(fn):
        try:
            fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError("expected a ClientError against the deleted archive, call succeeded")

    gone = f"Archive {archive_name} does not exist."
    describe_code, describe_message = _error(lambda: ev.describe_archive(ArchiveName=archive_name))
    assert describe_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from DescribeArchive, got {describe_code}"
    )
    assert describe_message == gone, f"expected {gone!r} from DescribeArchive, got {describe_message!r}"

    update_code, update_message = _error(
        lambda: ev.update_archive(ArchiveName=archive_name, Description="post-delete-mutation-probe")
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from UpdateArchive on a deleted archive, got {update_code}"
    )
    assert update_message == gone, f"expected {gone!r} from UpdateArchive, got {update_message!r}"

    ev.create_archive(ArchiveName=archive_name, EventSourceArn=bus_resp['EventBusArn'])
    recreated = ev.describe_archive(ArchiveName=archive_name)
    assert recreated["ArchiveName"] == archive_name, (
        f"expected the freed archive name to be reusable, got {recreated!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
