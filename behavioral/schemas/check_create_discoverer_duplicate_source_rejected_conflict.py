"""create-discoverer-duplicate-source-rejected-conflict."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-discoverer-duplicate-source-rejected-conflict"
GROUP = "overly-permissive"
SERVICES = ["schemas"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateDiscoverer on the same SourceArn is rejected as ConflictException; the first is unaffected."""
    events = ctx.client("events")
    schemas = ctx.client("schemas")

    tag_kv = [{"Key": "sim2real-check", "Value": CHECK}]
    tag_map = {"sim2real-check": CHECK}

    bus_name = ctx.unique_name("sim2real-schemas-bus-")
    bus_arn = events.create_event_bus(Name=bus_name, Tags=tag_kv)["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus_name))

    first = schemas.create_discoverer(SourceArn=bus_arn, Description="first", Tags=tag_map)
    first_id = first["DiscovererId"]
    ctx.on_cleanup(lambda: schemas.delete_discoverer(DiscovererId=first_id))

    err = _error(lambda: schemas.create_discoverer(SourceArn=bus_arn, Description="second"))
    assert err["Code"] == "ConflictException", f"expected ConflictException on duplicate SourceArn, got {err!r}"
    assert err["Message"] == f"Discoverer {first_id} already exists.", f"unexpected discoverer_dup message: {err['Message']!r}"

    unaffected = schemas.describe_discoverer(DiscovererId=first_id)
    assert unaffected["Description"] == "first", (
        f"expected the first discoverer's Description to be unaffected by the rejected duplicate, "
        f"got {unaffected['Description']!r}"
    )
    assert unaffected["SourceArn"] == bus_arn, (
        f"expected the first discoverer's SourceArn to be unaffected by the rejected duplicate, "
        f"got {unaffected['SourceArn']!r}"
    )

    # Positive control: a discoverer on a genuinely different event bus still succeeds.
    other_bus_name = ctx.unique_name("sim2real-schemas-bus2-")
    other_bus_arn = events.create_event_bus(Name=other_bus_name, Tags=tag_kv)["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=other_bus_name))
    control = schemas.create_discoverer(SourceArn=other_bus_arn, Description="control", Tags=tag_map)
    control_id = control["DiscovererId"]
    ctx.on_cleanup(lambda: schemas.delete_discoverer(DiscovererId=control_id))

    control_read = schemas.describe_discoverer(DiscovererId=control_id)
    assert control_read["State"] == "STARTED", (
        f"expected the control discoverer on a distinct SourceArn to be STARTED via an independent "
        f"read, got {control_read['State']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
