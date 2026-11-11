"""origin-endpoint-container-manifest-mismatch-rejected."""
from __future__ import annotations

from typing import Any, Callable, Optional

from behavioral_harness import tags

CHECK = "origin-endpoint-container-manifest-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackagev2"]

# AWS ends this message with a trailing space.
TS_WITH_DASH = (
    "Validation error encountered at request: DASH manifest is not supported on endpoint with "
    "TS container type. "
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateOriginEndpoint with ContainerType=TS and a DashManifests entry fails ValidationException
    TS_CONTAINER_TYPE_WITH_DASH_MANIFEST with the exact message and creates nothing, while the same DASH
    manifest on a CMAF endpoint is created and read back."""
    mp = ctx.client("mediapackagev2")

    group_name = ctx.unique_name("sim2real-mpv2-cg-")
    mp.create_channel_group(ChannelGroupName=group_name)
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))

    channel_name = ctx.unique_name("sim2real-mpv2-ch-")
    mp.create_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    ctx.on_cleanup(
        lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    )

    bad_endpoint = ctx.unique_name("sim2real-mpv2-oe-bad-")
    err = _client_error(
        lambda: mp.create_origin_endpoint(
            ChannelGroupName=group_name,
            ChannelName=channel_name,
            OriginEndpointName=bad_endpoint,
            ContainerType="TS",
            DashManifests=[{"ManifestName": "dash"}],
        )
    )
    assert err is not None, "expected TS container + DASH manifest to be rejected"
    assert err.response["Error"]["Code"] == "ValidationException", (
        f"expected ValidationException, got {err.response['Error']['Code']}"
    )
    message = err.response["Error"]["Message"]
    assert message == TS_WITH_DASH, f"expected message {TS_WITH_DASH!r}, got {message!r}"
    assert err.response.get("ValidationExceptionType") == "TS_CONTAINER_TYPE_WITH_DASH_MANIFEST", (
        f"expected TS_CONTAINER_TYPE_WITH_DASH_MANIFEST, got {err.response.get('ValidationExceptionType')}"
    )

    # effect absent: no endpoint with that name was created
    names = {
        e["OriginEndpointName"]
        for e in mp.list_origin_endpoints(
            ChannelGroupName=group_name, ChannelName=channel_name
        )["Items"]
    }
    assert bad_endpoint not in names, f"rejected endpoint {bad_endpoint} was created anyway"

    # positive control: the same DASH manifest under a CMAF container succeeds
    good_endpoint = ctx.unique_name("sim2real-mpv2-oe-good-")
    mp.create_origin_endpoint(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=good_endpoint,
        ContainerType="CMAF",
        DashManifests=[{"ManifestName": "dash"}],
    )
    ctx.on_cleanup(
        lambda: mp.delete_origin_endpoint(
            ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=good_endpoint
        )
    )

    # terminal assertion: an independent read at the destination, not the create call's own echo
    fetched = mp.get_origin_endpoint(
        ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=good_endpoint
    )
    assert fetched["ContainerType"] == "CMAF", f"expected CMAF, got {fetched.get('ContainerType')}"
    assert fetched["DashManifests"][0]["ManifestName"] == "dash", (
        f"expected dash manifest, got {fetched.get('DashManifests')}"
    )


def _client_error(fn: Callable[[], Any]) -> Optional[Any]:
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as e:
        return e


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
