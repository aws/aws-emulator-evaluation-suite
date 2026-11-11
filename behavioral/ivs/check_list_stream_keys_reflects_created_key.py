"""list-stream-keys-reflects-created-key."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-stream-keys-reflects-created-key"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChannel implicitly provisions exactly one stream key; ListStreamKeys for
    that channel reflects it and only it."""
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-keys-")
    resp = ivs.create_channel(name=name, tags={"purpose": "sim2real"})
    arn = resp["channel"]["arn"]
    created_key_arn = resp["streamKey"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=arn))

    keys = ivs.list_stream_keys(channelArn=arn)["streamKeys"]
    assert len(keys) == 1, f"expected exactly 1 stream key, got {len(keys)}: {keys}"
    assert keys[0]["arn"] == created_key_arn, (
        f"expected stream key arn {created_key_arn!r}, got {keys[0]['arn']!r}"
    )
    assert keys[0]["channelArn"] == arn, (
        f"expected channelArn {arn!r}, got {keys[0]['channelArn']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
