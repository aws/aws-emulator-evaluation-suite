"""update-channel-description-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-channel-description-persists"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateChannel replaces the Description and DescribeChannel reflects the new value,
    while Id/Arn and the ingest endpoints are left unchanged by an unrelated field update."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-ch-")
    created = mp.create_channel(
        Id=channel_id, Description="original", Tags={"purpose": "behavioral-check"}
    )
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))
    original_endpoint_ids = {e["Id"] for e in created["HlsIngest"]["IngestEndpoints"]}

    updated = mp.update_channel(Id=channel_id, Description="updated-description")
    assert updated["Description"] == "updated-description", (
        f"expected UpdateChannel to echo the new Description, got {updated['Description']!r}"
    )
    assert updated["Id"] == channel_id, (
        f"expected UpdateChannel to echo Id {channel_id!r}, got {updated['Id']!r}"
    )
    assert updated["Arn"] == created["Arn"], (
        f"expected Arn unchanged by an unrelated field update: "
        f"{created['Arn']!r} != {updated['Arn']!r}"
    )

    described = mp.describe_channel(Id=channel_id)
    assert described["Description"] == "updated-description", (
        f"expected DescribeChannel to reflect the new Description, "
        f"got {described['Description']!r}"
    )
    described_endpoint_ids = {e["Id"] for e in described["HlsIngest"]["IngestEndpoints"]}
    assert described_endpoint_ids == original_endpoint_ids, (
        f"expected ingest endpoint ids unchanged by an unrelated field update: "
        f"{original_endpoint_ids!r} != {described_endpoint_ids!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
