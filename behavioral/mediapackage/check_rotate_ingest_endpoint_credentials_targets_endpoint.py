"""rotate-ingest-endpoint-credentials-targets-endpoint."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "rotate-ingest-endpoint-credentials-targets-endpoint"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RotateIngestEndpointCredentials regenerates only the targeted IngestEndpoint's
    credentials, leaves every other ingest endpoint on the channel untouched, and the
    new credentials persist through an independent DescribeChannel read."""
    mp = ctx.client("mediapackage")

    cid = ctx.unique_name("sim2real-mp-rie-")
    created = mp.create_channel(Id=cid, Tags={"sim2real": "rotate-ingest-endpoint-credentials-targets-endpoint"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=cid))

    before = created["HlsIngest"]["IngestEndpoints"]
    assert len(before) >= 2, (
        f"expected MediaPackage to provision redundant (>=2) ingest endpoints per channel, got {len(before)}"
    )
    before_by_id = {e["Id"]: e for e in before}
    endpoint_id = before[0]["Id"]

    rotated = mp.rotate_ingest_endpoint_credentials(Id=cid, IngestEndpointId=endpoint_id)
    rotated_by_id = {e["Id"]: e for e in rotated["HlsIngest"]["IngestEndpoints"]}
    target_before = before_by_id[endpoint_id]
    target_rotated = rotated_by_id[endpoint_id]

    assert target_rotated["Username"] != target_before["Username"], (
        f"expected rotated Username to differ from {target_before['Username']!r}, "
        f"got unchanged {target_rotated['Username']!r}"
    )
    assert target_rotated["Password"] != target_before["Password"], (
        f"expected rotated Password to differ from {target_before['Password']!r}, "
        f"got unchanged {target_rotated['Password']!r}"
    )

    described = mp.describe_channel(Id=cid)
    described_by_id = {e["Id"]: e for e in described["HlsIngest"]["IngestEndpoints"]}
    described_target = described_by_id[endpoint_id]

    assert described_target["Username"] == target_rotated["Username"], (
        f"DescribeChannel Username {described_target['Username']!r} != rotated "
        f"{target_rotated['Username']!r}"
    )
    assert described_target["Password"] == target_rotated["Password"], (
        f"DescribeChannel Password {described_target['Password']!r} != rotated "
        f"{target_rotated['Password']!r}"
    )

    for other_id, other_before in before_by_id.items():
        if other_id == endpoint_id:
            continue
        other_described = described_by_id[other_id]
        assert other_described["Username"] == other_before["Username"], (
            f"untargeted endpoint {other_id} Username changed: "
            f"{other_before['Username']!r} -> {other_described['Username']!r}"
        )
        assert other_described["Password"] == other_before["Password"], (
            f"untargeted endpoint {other_id} Password changed: "
            f"{other_before['Password']!r} -> {other_described['Password']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
