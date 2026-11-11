"""get-stream-key-returns-value-matches-create."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-stream-key-returns-value-matches-create"
GROUP = "data-plane"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The secret stream-key value returned by CreateChannel is durably stored and
    retrievable byte-for-byte via GetStreamKey."""
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-skval-")
    resp = ivs.create_channel(name=name, tags={"purpose": "sim2real"})
    channel_arn = resp["channel"]["arn"]
    key_arn = resp["streamKey"]["arn"]
    key_value = resp["streamKey"]["value"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=channel_arn))

    got = ivs.get_stream_key(arn=key_arn)["streamKey"]
    assert got["value"] == key_value, f"expected stream key value {key_value!r}, got {got['value']!r}"
    assert got["channelArn"] == channel_arn, f"expected channelArn {channel_arn!r}, got {got['channelArn']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
