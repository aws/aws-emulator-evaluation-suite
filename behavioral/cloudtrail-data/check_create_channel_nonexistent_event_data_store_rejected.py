"""create-channel-nonexistent-event-data-store-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-channel-nonexistent-event-data-store-rejected"
GROUP = "state"
SERVICES = ["cloudtrail-data"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateChannel to a well-formed but nonexistent event data store ARN fails with
    EventDataStoreNotFoundException, distinct from the ValidationException for a malformed
    Location, and neither rejected call leaves a channel behind."""
    cloudtrail = ctx.client("cloudtrail")
    account_id = _account_id(ctx)

    malformed_name = ctx.unique_name("sim2real-badch-ctl-")
    malformed_code, malformed_message = _create_channel_error(
        ctx, cloudtrail, malformed_name, "not a valid arn!!"
    )
    assert malformed_code == "ValidationException", (
        f"expected a Location violating the API's character-set pattern to be rejected "
        f"with ValidationException, got {malformed_code!r} ({malformed_message!r})"
    )
    assert malformed_message == (
        "1 validation error detected: Value at 'destinations.1.member.location' failed to satisfy "
        r"constraint: Member must satisfy regular expression pattern: ^[a-zA-Z0-9._/\-:*]+$"
    ), f"expected the Location pattern-violation message, got {malformed_message!r}"

    phantom_eds_arn = f"arn:aws:cloudtrail:{ctx.region}:{account_id}:eventdatastore/{uuid.uuid4()}"
    channel_name = ctx.unique_name("sim2real-badch-")
    code, message = _create_channel_error(ctx, cloudtrail, channel_name, phantom_eds_arn)
    assert code == "EventDataStoreNotFoundException", (
        f"unexpected error code for CreateChannel against a nonexistent event data "
        f"store: {code!r} ({message!r})"
    )
    assert message == f"The event data store {phantom_eds_arn} was not found.", (
        f"expected the not-found message naming the event data store, got {message!r}"
    )
    assert code != malformed_code, (
        "expected the well-formed-but-nonexistent-EDS rejection and the malformed-Location "
        f"rejection to be DIFFERENT error codes, both got {code!r}"
    )

    listing = cloudtrail.list_channels().get("Channels", [])
    leaked = [c for c in listing if c.get("Name") in (malformed_name, channel_name)]
    assert not leaked, f"expected no channel to be created after a rejected CreateChannel, found {leaked}"


def _create_channel_error(ctx, cloudtrail, name: str, location: str):
    try:
        resp = cloudtrail.create_channel(
            Name=name,
            Source="Custom",
            Destinations=[{"Type": "EVENT_DATA_STORE", "Location": location}],
        )
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    channel_arn = resp["ChannelArn"]
    ctx.on_cleanup(lambda: _delete_channel(cloudtrail, channel_arn))
    raise AssertionError(
        f"expected CreateChannel({name!r}, Destinations -> {location!r}) to be rejected, "
        f"but it created channel {channel_arn!r}"
    )


def _delete_channel(cloudtrail, arn: str) -> None:
    try:
        cloudtrail.delete_channel(Channel=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ChannelNotFoundException":
            raise


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
