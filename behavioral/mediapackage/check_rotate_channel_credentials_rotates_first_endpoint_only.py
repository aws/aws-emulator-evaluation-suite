"""rotate-channel-credentials-rotates-first-endpoint-only."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "rotate-channel-credentials-rotates-first-endpoint-only"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The deprecated RotateChannelCredentials regenerates only the first ingest endpoint's credentials;
    the second endpoint keeps its own, and DescribeChannel shows the same split."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-chan-")
    created = mp.create_channel(Id=channel_id, Tags={"created-by": "sim2real"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    before = created["HlsIngest"]["IngestEndpoints"]
    assert len(before) >= 2, (
        "expected MediaPackage to provision redundant (>=2) ingest endpoints per channel"
    )

    rotated = mp.rotate_channel_credentials(Id=channel_id)
    after = rotated["HlsIngest"]["IngestEndpoints"]
    assert len(after) == len(before)

    assert after[0]["Id"] == before[0]["Id"]
    assert after[0]["Username"] != before[0]["Username"] or after[0]["Password"] != before[0]["Password"], (
        "RotateChannelCredentials did not change the first ingest endpoint's credentials"
    )

    for before_ep, after_ep in zip(before[1:], after[1:]):
        assert before_ep["Id"] == after_ep["Id"]
        assert before_ep["Username"] == after_ep["Username"]
        assert before_ep["Password"] == after_ep["Password"], (
            "RotateChannelCredentials must not touch ingest endpoints other than the first"
        )

    described = mp.describe_channel(Id=channel_id)["HlsIngest"]["IngestEndpoints"]
    assert described[0]["Id"] == after[0]["Id"]
    assert described[0]["Username"] == after[0]["Username"]
    assert described[0]["Password"] == after[0]["Password"], (
        "the rotated first endpoint's new credentials must persist through DescribeChannel"
    )
    for before_ep, described_ep in zip(before[1:], described[1:]):
        assert described_ep["Id"] == before_ep["Id"]
        assert described_ep["Username"] == before_ep["Username"]
        assert described_ep["Password"] == before_ep["Password"], (
            "DescribeChannel must still show the untouched endpoints' original credentials"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
