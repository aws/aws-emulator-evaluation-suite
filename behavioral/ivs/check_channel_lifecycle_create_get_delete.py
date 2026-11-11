"""channel-lifecycle-create-get-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "channel-lifecycle-create-get-delete"
GROUP = "lifecycle"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChannel returns a channel+streamKey pair; GetChannel reflects them; after
    DeleteChannel, GetChannel on the same ARN raises ResourceNotFoundException."""
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-chan-")

    resp = ivs.create_channel(
        name=name, latencyMode="LOW", type="STANDARD", tags={"purpose": "sim2real"}
    )
    channel = resp["channel"]
    arn = channel["arn"]
    stream_key = resp["streamKey"]

    deleted = {"done": False}

    def _cleanup():
        if not deleted["done"]:
            try:
                ivs.delete_channel(arn=arn)
            except ClientError as e:
                if e.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_cleanup)

    assert channel["name"] == name, f"expected channel name {name!r}, got {channel['name']!r}"
    assert channel["latencyMode"] == "LOW", (
        f"expected latencyMode LOW, got {channel['latencyMode']!r}"
    )
    assert channel["type"] == "STANDARD", f"expected type STANDARD, got {channel['type']!r}"
    assert channel["ingestEndpoint"], "expected a non-empty ingestEndpoint"
    assert channel["playbackUrl"].startswith("https://"), (
        f"expected playbackUrl to start with https://, got {channel['playbackUrl']!r}"
    )
    assert stream_key["channelArn"] == arn, (
        f"expected streamKey.channelArn {arn!r}, got {stream_key['channelArn']!r}"
    )
    assert stream_key["value"], "expected a non-empty streamKey value"

    got = ivs.get_channel(arn=arn)["channel"]
    assert got["arn"] == arn, f"expected GetChannel arn {arn!r}, got {got['arn']!r}"
    assert got["name"] == name, f"expected GetChannel name {name!r}, got {got['name']!r}"

    ivs.delete_channel(arn=arn)
    deleted["done"] = True

    try:
        ivs.get_channel(arn=arn)
        raise AssertionError("GetChannel succeeded after DeleteChannel")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException from GetChannel on deleted arn, got {code!r}"
        )
        message = e.response["Error"]["Message"]
        assert message == f"Resource: {arn} not found", (
            f"unexpected GetChannel not-found message: {message!r}"
        )

    try:
        ivs.update_channel(arn=arn, latencyMode="NORMAL")
        raise AssertionError("UpdateChannel succeeded on a deleted channel arn")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException from UpdateChannel on deleted arn, got {code!r}"
        )
        message = e.response["Error"]["Message"]
        assert message == f"Resource: {arn} not found", (
            f"unexpected UpdateChannel not-found message: {message!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
