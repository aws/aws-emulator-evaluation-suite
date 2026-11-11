"""create-channel-generates-unique-ingest-credentials."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-channel-generates-unique-ingest-credentials"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChannel auto-generates distinct HLS ingest credentials/URL per channel."""
    mp = ctx.client("mediapackage")

    id1 = ctx.unique_name("sim2real-mp-ch-")
    c1 = mp.create_channel(Id=id1, Tags={"created-by": "sim2real"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=id1))

    id2 = ctx.unique_name("sim2real-mp-ch-")
    c2 = mp.create_channel(Id=id2, Tags={"created-by": "sim2real"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=id2))

    ep1 = c1["HlsIngest"]["IngestEndpoints"][0]
    ep2 = c2["HlsIngest"]["IngestEndpoints"][0]

    assert ep1["Username"] and ep1["Password"] and ep1["Url"], (
        f"channel {id1} missing generated ingest credentials: {ep1}"
    )
    assert ep2["Username"] and ep2["Password"] and ep2["Url"], (
        f"channel {id2} missing generated ingest credentials: {ep2}"
    )
    assert ep1["Username"] != ep2["Username"], "usernames must be unique per channel"
    assert ep1["Password"] != ep2["Password"], "passwords must be unique per channel"
    assert ep1["Url"] != ep2["Url"], "ingest URLs must be unique per channel"

    # credentials must also be readable back via DescribeChannel
    described = mp.describe_channel(Id=id1)
    described_ep = described["HlsIngest"]["IngestEndpoints"][0]
    assert described_ep["Id"] == ep1["Id"], (
        f"DescribeChannel endpoint id {described_ep['Id']!r} != CreateChannel id {ep1['Id']!r}"
    )
    assert described_ep["Url"] == ep1["Url"], (
        f"DescribeChannel url {described_ep['Url']!r} != CreateChannel url {ep1['Url']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
