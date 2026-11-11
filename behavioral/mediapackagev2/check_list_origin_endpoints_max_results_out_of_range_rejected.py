"""list-origin-endpoints-max-results-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-origin-endpoints-max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackagev2"]


def _error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected rejection, but call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListOriginEndpoints with MaxResults=1001 (documented range 1-100) fails ValidationException with the
    exact message from the service, while a valid MaxResults lists the created endpoint."""
    mp = ctx.client("mediapackagev2")
    group = ctx.unique_name("sim2real-mpkg-cg-")
    channel = ctx.unique_name("sim2real-mpkg-ch-")
    endpoint = ctx.unique_name("sim2real-mpkg-oe-")
    mp.create_channel_group(ChannelGroupName=group, Tags={"purpose": "behavioral"})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group))
    mp.create_channel(
        ChannelGroupName=group, ChannelName=channel, Tags={"purpose": "behavioral"}
    )
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group, ChannelName=channel))
    mp.create_origin_endpoint(
        ChannelGroupName=group,
        ChannelName=channel,
        OriginEndpointName=endpoint,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index"}],
        Tags={"purpose": "behavioral"},
    )
    ctx.on_cleanup(
        lambda: mp.delete_origin_endpoint(
            ChannelGroupName=group, ChannelName=channel, OriginEndpointName=endpoint
        )
    )

    err = _error(
        lambda: mp.list_origin_endpoints(
            ChannelGroupName=group, ChannelName=channel, MaxResults=1001
        )
    )
    assert err["Code"] == "ValidationException", f"got {err!r}"
    expected_message = (
        "Validation error encountered at request.maxResults: Member must have value less than "
        "or equal to 100. Check the value you specified in your request and then try again"
    )
    assert err["Message"] == expected_message, f"got {err!r}"

    # Positive control: an in-range MaxResults succeeds and finds the endpoint.
    page = mp.list_origin_endpoints(
        ChannelGroupName=group, ChannelName=channel, MaxResults=50
    )
    names = {item["OriginEndpointName"] for item in page["Items"]}
    assert endpoint in names, f"expected {endpoint!r} in {names}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
