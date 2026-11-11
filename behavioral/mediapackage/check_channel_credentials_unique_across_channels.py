"""channel-credentials-unique-across-channels."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "channel-credentials-unique-across-channels"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two distinct Channels get independently generated ingest credentials --
    the system must not hand out the same username/password pair twice."""
    mp = ctx.client("mediapackage")

    channel_a = ctx.unique_name("sim2real-mp-chan-a-")
    channel_b = ctx.unique_name("sim2real-mp-chan-b-")
    mp.create_channel(Id=channel_a)
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_a))
    mp.create_channel(Id=channel_b)
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_b))

    # Independent read at the destination, through DescribeChannel rather than the
    # CreateChannel responses that just minted these credentials.
    described_a = mp.describe_channel(Id=channel_a)
    described_b = mp.describe_channel(Id=channel_b)
    ep_a = described_a["HlsIngest"]["IngestEndpoints"][0]
    ep_b = described_b["HlsIngest"]["IngestEndpoints"][0]

    assert ep_a["Username"] != ep_b["Username"], (
        "two different channels received the same generated ingest username"
    )
    assert ep_a["Password"] != ep_b["Password"], (
        "two different channels received the same generated ingest password"
    )
    assert ep_a["Url"] != ep_b["Url"], (
        "two different channels received the same generated ingest url"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
