"""create-channel-default-values."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-channel-default-values"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChannel applies documented defaults and auto-creates exactly one stream key."""
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-chan-")
    resp = ivs.create_channel(name=name)
    channel = resp["channel"]
    stream_key = resp["streamKey"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=channel["arn"]))

    # Documented defaults (see Channel shape docs): latencyMode=LOW, type=STANDARD,
    # authorized=false, insecureIngest=false, containerFormat=TS.
    assert channel["latencyMode"] == "LOW", f"expected latencyMode=LOW, got {channel['latencyMode']!r}"
    assert channel["type"] == "STANDARD", f"expected type=STANDARD, got {channel['type']!r}"
    assert channel["authorized"] is False, f"expected authorized=False, got {channel['authorized']!r}"
    assert channel["insecureIngest"] is False, (
        f"expected insecureIngest=False, got {channel['insecureIngest']!r}"
    )
    assert channel["containerFormat"] == "TS", (
        f"expected containerFormat=TS, got {channel['containerFormat']!r}"
    )
    assert channel["name"] == name, f"expected name={name!r}, got {channel['name']!r}"
    assert channel["ingestEndpoint"], "expected a non-empty ingestEndpoint, got falsy value"
    assert channel["playbackUrl"], "expected a non-empty playbackUrl, got falsy value"

    # CreateChannel auto-creates exactly one stream key scoped to the new channel.
    assert stream_key["channelArn"] == channel["arn"], (
        f"expected streamKey.channelArn={channel['arn']!r}, got {stream_key['channelArn']!r}"
    )
    assert stream_key["value"], "expected a non-empty streamKey.value, got falsy value"

    keys = ivs.list_stream_keys(channelArn=channel["arn"])["streamKeys"]
    assert len(keys) == 1, f"expected exactly 1 stream key for channel, got {len(keys)}"
    assert keys[0]["arn"] == stream_key["arn"], (
        f"expected ListStreamKeys to return arn={stream_key['arn']!r}, got {keys[0]['arn']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
