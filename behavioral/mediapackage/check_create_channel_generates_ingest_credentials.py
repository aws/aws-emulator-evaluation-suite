"""create-channel-generates-ingest-credentials."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-channel-generates-ingest-credentials"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChannel provisions redundant HLS ingest endpoints with system-generated
    credentials, and DescribeChannel returns the SAME persisted credentials (not
    freshly regenerated on every read)."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-chan-")
    created = mp.create_channel(
        Id=channel_id,
        Description="fidelity check channel",
        Tags={"created-by": "sim2real"},
    )
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    endpoints = created["HlsIngest"]["IngestEndpoints"]
    assert len(endpoints) >= 2, (
        f"expected MediaPackage to provision redundant (>=2) ingest endpoints on "
        f"create, got {len(endpoints)}"
    )
    for ep in endpoints:
        assert ep["Username"], "ingest endpoint missing generated username"
        assert ep["Password"], "ingest endpoint missing generated password"
        assert ep["Url"], "ingest endpoint missing generated url"

    described = mp.describe_channel(Id=channel_id)
    described_endpoints = described["HlsIngest"]["IngestEndpoints"]
    assert len(described_endpoints) == len(endpoints)
    for created_ep, described_ep in zip(endpoints, described_endpoints):
        assert created_ep["Id"] == described_ep["Id"]
        assert created_ep["Username"] == described_ep["Username"], (
            "DescribeChannel returned different credentials than CreateChannel; "
            "credentials must be persisted, not regenerated on read"
        )
        assert created_ep["Password"] == described_ep["Password"], (
            "DescribeChannel returned a different password than CreateChannel; "
            "credentials must be persisted, not regenerated on read"
        )
        assert created_ep["Url"] == described_ep["Url"], (
            "DescribeChannel returned a different ingest URL than CreateChannel; "
            "the URL must be persisted, not regenerated on read"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
