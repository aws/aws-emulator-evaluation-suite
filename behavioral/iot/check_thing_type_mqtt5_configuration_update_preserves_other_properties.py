"""thing-type-mqtt5-configuration-update-preserves-other-properties."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "thing-type-mqtt5-configuration-update-preserves-other-properties"
GROUP = "thing-type"
SERVICES = ["iot"]

_DELETE_WAIT_S = 360.0
_DELETE_POLL_S = 15.0


def _teardown_thing_type(iot, name: str) -> None:
    """Deprecate, then delete once AWS's 5-minute post-deprecation hold clears.

    A failed delete raises once the wait budget runs out; AWS's own not-found codes mean the
    type is already gone.
    """
    try:
        iot.deprecate_thing_type(thingTypeName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + _DELETE_WAIT_S
    while True:
        try:
            iot.delete_thing_type(thingTypeName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code == "InvalidRequestException" and time.monotonic() < deadline:
                time.sleep(_DELETE_POLL_S)
                continue
            raise


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateThingType carrying only mqtt5Configuration.propagatingAttributes answers 200,
    and DescribeThingType then shows it beside the description, searchableAttributes, id and
    ARN that CreateThingType set, unchanged.
    """
    iot = ctx.client("iot")
    type_name = ctx.unique_name("sim2real-behav-thingtype-mqtt5-")
    description = "temperature and humidity sensor thing type"
    searchable = ["firmwareVersion", "model"]

    created = iot.create_thing_type(
        thingTypeName=type_name,
        thingTypeProperties={
            "thingTypeDescription": description,
            "searchableAttributes": searchable,
        },
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda _n=type_name: _teardown_thing_type(iot, _n))

    baseline = iot.describe_thing_type(thingTypeName=type_name)
    baseline_props = baseline["thingTypeProperties"]
    assert baseline_props["thingTypeDescription"] == description, (
        f"expected thingTypeDescription {description!r}, got {baseline_props!r}"
    )
    assert baseline_props["searchableAttributes"] == searchable, (
        f"expected searchableAttributes {searchable!r}, got {baseline_props!r}"
    )
    assert "mqtt5Configuration" not in baseline_props, (
        f"expected no mqtt5Configuration before any MQTT5 update, got {baseline_props!r}"
    )

    propagating = [
        {"userPropertyKey": "fleet:model", "thingAttribute": "model"},
        {"userPropertyKey": "fleet:client", "connectionAttribute": "iot:ClientId"},
    ]
    response = iot.update_thing_type(
        thingTypeName=type_name,
        thingTypeProperties={"mqtt5Configuration": {"propagatingAttributes": propagating}},
    )
    status = response["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected UpdateThingType to answer 200, got {status}"

    after = iot.describe_thing_type(thingTypeName=type_name)
    after_props = after["thingTypeProperties"]
    assert after_props["mqtt5Configuration"]["propagatingAttributes"] == propagating, (
        f"expected propagatingAttributes {propagating!r}, got {after_props!r}"
    )
    assert after_props["thingTypeDescription"] == description, (
        f"mqtt5Configuration-only update changed thingTypeDescription: {after_props!r}"
    )
    assert after_props["searchableAttributes"] == searchable, (
        f"mqtt5Configuration-only update changed searchableAttributes: {after_props!r}"
    )
    assert after["thingTypeId"] == created["thingTypeId"], (
        f"expected thingTypeId {created['thingTypeId']!r} to survive the update, got {after['thingTypeId']!r}"
    )
    assert after["thingTypeArn"] == created["thingTypeArn"], (
        f"expected thingTypeArn {created['thingTypeArn']!r} to survive the update, got {after['thingTypeArn']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
