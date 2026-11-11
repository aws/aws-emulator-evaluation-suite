"""rotate-ingest-endpoint-credentials-changes-credentials."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "rotate-ingest-endpoint-credentials-changes-credentials"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RotateIngestEndpointCredentials regenerates Username/Password for the targeted
    IngestEndpoint (same Id, same Url) and the new credentials are visible via
    DescribeChannel afterward."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-ch-")
    created = mp.create_channel(Id=channel_id, Tags={"created-by": "sim2real"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    before = created["HlsIngest"]["IngestEndpoints"][0]
    endpoint_id = before["Id"]

    rotated = mp.rotate_ingest_endpoint_credentials(Id=channel_id, IngestEndpointId=endpoint_id)
    after = next(e for e in rotated["HlsIngest"]["IngestEndpoints"] if e["Id"] == endpoint_id)

    assert after["Id"] == before["Id"], (
        f"rotation must target the same endpoint id, expected {before['Id']!r} got {after['Id']!r}"
    )
    assert after["Url"] == before["Url"], (
        f"rotation must not change the ingest URL, expected {before['Url']!r} got {after['Url']!r}"
    )
    assert (after["Username"], after["Password"]) != (before["Username"], before["Password"]), (
        "credentials must change after rotation"
    )

    described = mp.describe_channel(Id=channel_id)
    described_ep = next(
        e for e in described["HlsIngest"]["IngestEndpoints"] if e["Id"] == endpoint_id
    )
    assert described_ep["Username"] == after["Username"], (
        f"DescribeChannel must reflect the rotated username, expected {after['Username']!r} "
        f"got {described_ep['Username']!r}"
    )
    assert described_ep["Password"] == after["Password"], (
        f"DescribeChannel must reflect the rotated password, expected {after['Password']!r} "
        f"got {described_ep['Password']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
