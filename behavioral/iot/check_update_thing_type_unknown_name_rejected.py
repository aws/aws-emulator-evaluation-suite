"""update-thing-type-unknown-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-thing-type-unknown-name-rejected"
GROUP = "thing-type"
SERVICES = ["iot"]


def expect_error(fn, code, message):
    """Call fn(); assert the ClientError it raises carries exactly (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == code, f"expected {code}, got {err.get('Code')}: {err.get('Message')!r}"
        assert err.get("Message") == message, f"expected message {message!r}, got {err.get('Message')!r}"
        return
    raise AssertionError(f"expected {code}, but the call succeeded and returned {result!r}")


def _dissolve_thing_type(iot, name: str, *, budget_s: float = 420.0, poll_s: float = 20.0) -> None:
    """Deprecate a thing type, then retry DeleteThingType past AWS's post-deprecation cooldown
    ("wait for 5 minutes") until it succeeds or the type is already gone."""
    try:
        iot.deprecate_thing_type(thingTypeName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    give_up_at = time.monotonic() + budget_s
    while True:
        try:
            iot.delete_thing_type(thingTypeName=name)
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ResourceNotFoundException":
                return
            cooling_down = (
                err["Code"] == "InvalidRequestException" and "5 minutes" in err.get("Message", "")
            )
            if not cooling_down or time.monotonic() >= give_up_at:
                raise
        time.sleep(poll_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateThingType on a name that was never created is refused with ResourceNotFoundException,
    while the same call against an existing thing type succeeds and is visible on a later
    DescribeThingType."""
    iot = ctx.client("iot")
    existing_name = ctx.unique_name("sim2real-behav-thingtype-")
    missing_name = ctx.unique_name("sim2real-behav-thingtype-missing-")

    iot.create_thing_type(
        thingTypeName=existing_name,
        thingTypeProperties={"thingTypeDescription": "sim2real update target"},
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _dissolve_thing_type(iot, existing_name))

    _update_missing = (
        "ResourceNotFoundException",
        f"Thing Type {ctx.account}:{missing_name} not found.",
    )
    expect_error(
        lambda: iot.update_thing_type(
            thingTypeName=missing_name,
            thingTypeProperties={
                "mqtt5Configuration": {
                    "propagatingAttributes": [
                        {"userPropertyKey": "model.tag", "thingAttribute": "model"}
                    ]
                }
            },
        ),
        *_update_missing,
    )

    _describe_missing = (
        "ResourceNotFoundException",
        f"Thing Type {ctx.account}:{missing_name} not found.",
    )
    expect_error(lambda: iot.describe_thing_type(thingTypeName=missing_name), *_describe_missing)

    # Positive control: the identical UpdateThingType call succeeds against a thing type
    # that was actually created.
    iot.update_thing_type(
        thingTypeName=existing_name,
        thingTypeProperties={
            "mqtt5Configuration": {
                "propagatingAttributes": [
                    {"userPropertyKey": "model.tag", "thingAttribute": "model"}
                ]
            }
        },
    )

    described = iot.describe_thing_type(thingTypeName=existing_name)
    props = described["thingTypeProperties"]
    assert props.get("mqtt5Configuration", {}).get("propagatingAttributes") == [
        {"userPropertyKey": "model.tag", "thingAttribute": "model"}
    ], f"UpdateThingType's effect is not visible on a later DescribeThingType: {props!r}"
    assert props["thingTypeDescription"] == "sim2real update target", (
        f"the update must not disturb the creation-time description: {props!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
