"""rotate-channel-credentials-regenerates-credentials."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "rotate-channel-credentials-regenerates-credentials"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RotateChannelCredentials regenerates the ingest endpoint's Username/Password
    while preserving its Id/Url, and the change is durably visible via DescribeChannel."""
    mp = ctx.client("mediapackage")

    cid = ctx.unique_name("sim2real-mp-rot-")
    created = mp.create_channel(Id=cid, Tags={"purpose": "behavioral-check"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=cid))

    before = created["HlsIngest"]["IngestEndpoints"][0]

    rotated = mp.rotate_channel_credentials(Id=cid)
    after = rotated["HlsIngest"]["IngestEndpoints"][0]

    assert after["Id"] == before["Id"], "rotating credentials must not change the endpoint Id"
    assert after["Url"] == before["Url"], "rotating credentials must not change the ingest URL"
    assert after["Username"] != before["Username"], "username must be regenerated"
    assert after["Password"] != before["Password"], "password must be regenerated"

    described = mp.describe_channel(Id=cid)
    described_ep = described["HlsIngest"]["IngestEndpoints"][0]
    assert described_ep["Username"] == after["Username"], (
        f"DescribeChannel username {described_ep['Username']!r} does not match the "
        f"rotated username {after['Username']!r}; rotated credentials must be durably persisted"
    )
    assert described_ep["Password"] == after["Password"], (
        f"DescribeChannel password does not match the rotated password "
        f"(expected {after['Password']!r}, got {described_ep['Password']!r}); "
        "rotated credentials must be durably persisted"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
