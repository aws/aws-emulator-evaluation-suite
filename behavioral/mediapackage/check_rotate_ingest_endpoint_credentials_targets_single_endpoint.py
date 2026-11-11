"""rotate-ingest-endpoint-credentials-targets-single-endpoint."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "rotate-ingest-endpoint-credentials-targets-single-endpoint"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RotateIngestEndpointCredentials regenerates the credentials of exactly the named IngestEndpoint and
    leaves the channel's other ingest endpoint unchanged, as DescribeChannel shows."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-chan-")
    created = mp.create_channel(Id=channel_id, Tags={"scope": "channel"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    before = created["HlsIngest"]["IngestEndpoints"]
    assert len(before) >= 2, (
        "expected MediaPackage to provision redundant (>=2) ingest endpoints per channel"
    )
    target = before[-1]

    mp.rotate_ingest_endpoint_credentials(Id=channel_id, IngestEndpointId=target["Id"])

    described = mp.describe_channel(Id=channel_id)
    after = described["HlsIngest"]["IngestEndpoints"]
    after_by_id = {ep["Id"]: ep for ep in after}

    target_after = after_by_id[target["Id"]]
    assert (
        target_after["Username"] != target["Username"] or target_after["Password"] != target["Password"]
    ), "RotateIngestEndpointCredentials did not change the targeted endpoint's credentials"

    for other in before:
        if other["Id"] == target["Id"]:
            continue
        other_after = after_by_id[other["Id"]]
        assert other_after["Username"] == other["Username"], (
            "RotateIngestEndpointCredentials must not rotate the username of an untargeted endpoint"
        )
        assert other_after["Password"] == other["Password"], (
            "RotateIngestEndpointCredentials must not rotate credentials of an untargeted endpoint"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
