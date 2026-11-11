"""list-stream-keys-reflects-auto-created-key."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-stream-keys-reflects-auto-created-key"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChannel implicitly provisions exactly one stream key, and ListStreamKeys for that
    channel returns exactly that key."""
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-chan-")
    created = ivs.create_channel(name=name, tags={"purpose": "sim2real"})
    channel_arn = created["channel"]["arn"]
    auto_key_arn = created["streamKey"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=channel_arn))

    keys = ivs.list_stream_keys(channelArn=channel_arn)["streamKeys"]
    assert len(keys) == 1, f"expected exactly 1 stream key, got {len(keys)}: {keys}"
    assert keys[0]["arn"] == auto_key_arn, (
        f"expected the listed key to be the auto-created key {auto_key_arn!r}, "
        f"got {keys[0]['arn']!r}"
    )
    assert keys[0]["channelArn"] == channel_arn, (
        f"expected listed key's channelArn to be {channel_arn!r}, got {keys[0]['channelArn']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
