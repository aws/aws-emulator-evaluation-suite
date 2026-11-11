"""origin-endpoint-container-type-immutable-rejected."""
from __future__ import annotations

from typing import Any, Callable, Optional

from behavioral_harness import tags

CHECK = "origin-endpoint-container-type-immutable-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackagev2"]

CONTAINER_TYPE_IMMUTABLE = (
    "Validation error encountered at request.containerType: You can't change the container "
    "type after you create an origin endpoint. To use a different container type, you'll "
    "need to create a new origin endpoint"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateOriginEndpoint changing ContainerType from TS to CMAF fails ValidationException
    CONTAINER_TYPE_IMMUTABLE with the exact message and leaves ContainerType and ETag unchanged, while an
    update that only changes Description succeeds."""
    mp = ctx.client("mediapackagev2")

    group_name = ctx.unique_name("sim2real-mpv2-cg-")
    mp.create_channel_group(ChannelGroupName=group_name, Tags={"purpose": "behavioral"})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))

    channel_name = ctx.unique_name("sim2real-mpv2-ch-")
    mp.create_channel(
        ChannelGroupName=group_name, ChannelName=channel_name, Tags={"purpose": "behavioral"}
    )
    ctx.on_cleanup(
        lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    )

    endpoint_name = ctx.unique_name("sim2real-mpv2-oe-")
    created = mp.create_origin_endpoint(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=endpoint_name,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index", "ManifestWindowSeconds": 60}],
        Tags={"purpose": "behavioral"},
    )
    ctx.on_cleanup(
        lambda: mp.delete_origin_endpoint(
            ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name
        )
    )
    etag = created["ETag"]

    err = _client_error(
        lambda: mp.update_origin_endpoint(
            ChannelGroupName=group_name,
            ChannelName=channel_name,
            OriginEndpointName=endpoint_name,
            ContainerType="CMAF",
            # The manifest is carried over so the only rejected change is the container type.
            HlsManifests=[{"ManifestName": "index", "ManifestWindowSeconds": 60}],
            ETag=etag,
        )
    )
    assert err is not None, "expected ContainerType mutation to be rejected"
    assert err.response["Error"]["Code"] == "ValidationException", err.response
    assert err.response.get("ValidationExceptionType") == "CONTAINER_TYPE_IMMUTABLE", (
        f"expected CONTAINER_TYPE_IMMUTABLE, got {err.response.get('ValidationExceptionType')}"
    )
    message = err.response["Error"]["Message"]
    assert message == CONTAINER_TYPE_IMMUTABLE, f"expected message {CONTAINER_TYPE_IMMUTABLE!r}, got {message!r}"

    # effect absent: ContainerType still TS, ETag unchanged
    still = mp.get_origin_endpoint(
        ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name
    )
    assert still["ContainerType"] == "TS", (
        f"expected ContainerType unchanged at TS, got {still['ContainerType']!r}"
    )
    assert still["ETag"] == etag, f"expected ETag unchanged at {etag!r}, got {still['ETag']!r}"

    # positive control: same ContainerType, different Description, succeeds
    updated = mp.update_origin_endpoint(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=endpoint_name,
        ContainerType="TS",
        Description="now with a description",
        HlsManifests=[{"ManifestName": "index", "ManifestWindowSeconds": 60}],
        ETag=etag,
    )
    assert updated["Description"] == "now with a description", (
        f"expected Description update to persist, got {updated['Description']!r}"
    )
    assert updated["ContainerType"] == "TS", (
        f"expected ContainerType unchanged at TS, got {updated['ContainerType']!r}"
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
