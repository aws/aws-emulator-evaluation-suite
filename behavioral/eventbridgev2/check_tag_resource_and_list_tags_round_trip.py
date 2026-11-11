"""tag-resource-and-list-tags-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-and-list-tags-round-trip"
GROUP = "tagging"
SERVICES = ["eventbridgev2"]

_ACTIVE_TIMEOUT_S = 60.0


def _teardown_bus(ebv2, bus_arn: str):
    """Delete the bus, waiting out a transient CREATING/DELETING rather than hiding it."""

    def run_undo() -> None:
        deadline = time.monotonic() + _ACTIVE_TIMEOUT_S
        while True:
            try:
                ebv2.delete_event_bus(EventBusArn=bus_arn)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code != "InvalidStateException" or time.monotonic() > deadline:
                    raise
                time.sleep(2)

    return run_undo


def _wait_bus_active(ebv2, bus_arn: str) -> None:
    deadline = time.monotonic() + _ACTIVE_TIMEOUT_S
    while True:
        described = ebv2.describe_event_bus(EventBusArn=bus_arn)
        if described["State"] == "ACTIVE":
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"bus stayed {described['State']!r}, never reached ACTIVE")
        time.sleep(2)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags given at CreateEventBus are readable through ListTagsForResource, TagResource adds
    to them without disturbing the originals, and UntagResource removes only what it names.
    """
    ebv2 = ctx.client("eventbridgev2")
    bus_name = ctx.unique_name("sim2real-behav-ebv2-bus-")

    bus = ebv2.create_event_bus(
        Name=bus_name, ClientToken=ctx.unique_name("sim2real-behav-tok-"),
        Tags={"sim2real": CHECK, "origin": "create"},
    )
    bus_arn = bus["EventBusArn"]
    ctx.on_cleanup(_teardown_bus(ebv2, bus_arn))
    _wait_bus_active(ebv2, bus_arn)

    got = ebv2.list_tags_for_resource(ResourceArn=bus_arn)["Tags"]
    assert got == {"sim2real": CHECK, "origin": "create"}, (
        f"tags given at creation did not round-trip: got {got!r}"
    )

    ebv2.tag_resource(ResourceArn=bus_arn, Tags={"added": "later"})
    got = ebv2.list_tags_for_resource(ResourceArn=bus_arn)["Tags"]
    assert got == {"sim2real": CHECK, "origin": "create", "added": "later"}, (
        f"TagResource must add without disturbing existing tags: got {got!r}"
    )

    ebv2.untag_resource(ResourceArn=bus_arn, TagKeys=["origin"])
    got = ebv2.list_tags_for_resource(ResourceArn=bus_arn)["Tags"]
    assert got == {"sim2real": CHECK, "added": "later"}, (
        f"UntagResource must remove only the named key: got {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
