"""rotate-ingest-endpoint-credentials-invalid-endpoint-id-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "rotate-ingest-endpoint-credentials-invalid-endpoint-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackage"]


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RotateIngestEndpointCredentials with an IngestEndpointId not on the channel fails NotFoundException
    with the exact message and leaves every endpoint's credentials unchanged, while rotating a real
    IngestEndpointId changes them, as DescribeChannel confirms."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-chan-")
    created = mp.create_channel(Id=channel_id, Tags={"purpose": "behavioral-check"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    real_endpoints_before = created["HlsIngest"]["IngestEndpoints"]
    real_ids = {ep["Id"] for ep in real_endpoints_before}
    bogus_endpoint_id = "not-a-real-ingest-endpoint-id"
    assert bogus_endpoint_id not in real_ids, (
        f"test setup invalid: {bogus_endpoint_id!r} collides with a real endpoint id {real_ids!r}"
    )

    code, message = _error_code(
        lambda: mp.rotate_ingest_endpoint_credentials(
            Id=channel_id, IngestEndpointId=bogus_endpoint_id
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    # AWS's message carries a trailing space after the guid.
    expected_message = (
        f"channel with id={channel_id} does not have Ingest Endpoint with guid = {bogus_endpoint_id} "
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    described = mp.describe_channel(Id=channel_id)
    after_bogus_attempt = described["HlsIngest"]["IngestEndpoints"]
    for before_ep, after_ep in zip(real_endpoints_before, after_bogus_attempt):
        assert before_ep["Username"] == after_ep["Username"], (
            "a rejected rotation on a bogus endpoint id must not disturb real credentials"
        )
        assert before_ep["Password"] == after_ep["Password"], (
            "a rejected rotation on a bogus endpoint id must not disturb real credentials"
        )

    target = real_endpoints_before[0]
    rotated = mp.rotate_ingest_endpoint_credentials(Id=channel_id, IngestEndpointId=target["Id"])
    rotated_target = next(
        ep for ep in rotated["HlsIngest"]["IngestEndpoints"] if ep["Id"] == target["Id"]
    )
    assert (
        rotated_target["Username"] != target["Username"]
        or rotated_target["Password"] != target["Password"]
    ), "rotating a real IngestEndpointId must change its credentials (positive control)"

    reconfirmed = mp.describe_channel(Id=channel_id)
    reconfirmed_target = next(
        ep for ep in reconfirmed["HlsIngest"]["IngestEndpoints"] if ep["Id"] == target["Id"]
    )
    assert reconfirmed_target["Username"] == rotated_target["Username"], (
        "rotated credentials on a valid endpoint id must persist through an independent "
        f"DescribeChannel read: expected {rotated_target['Username']!r}, "
        f"got {reconfirmed_target['Username']!r}"
    )
    assert reconfirmed_target["Password"] == rotated_target["Password"], (
        "rotated credentials on a valid endpoint id must persist through an independent "
        "DescribeChannel read"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
