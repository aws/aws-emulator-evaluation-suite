"""update-origin-endpoint-container-type-immutable-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-origin-endpoint-container-type-immutable-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackagev2"]


def _error(fn):
    """Call fn(); return its error code, message and response. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"], e.response
    raise AssertionError(f"expected ContainerType mutation to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateOriginEndpoint cannot change ContainerType after creation (CONTAINER_TYPE_IMMUTABLE)."""
    mp = ctx.client("mediapackagev2")
    group_name = ctx.unique_name("sim2real-mpv2-grp-")
    channel_name = ctx.unique_name("sim2real-mpv2-ch-")
    endpoint_name = ctx.unique_name("sim2real-mpv2-oe-")

    mp.create_channel_group(ChannelGroupName=group_name, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    mp.create_channel(ChannelGroupName=group_name, ChannelName=channel_name, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name))
    created = mp.create_origin_endpoint(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=endpoint_name,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index"}],
        Tags={"sim2real": CHECK},
    )
    etag = created["ETag"]
    ctx.on_cleanup(
        lambda: mp.delete_origin_endpoint(
            ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name
        )
    )

    code, message, response = _error(
        lambda: mp.update_origin_endpoint(
            ChannelGroupName=group_name,
            ChannelName=channel_name,
            OriginEndpointName=endpoint_name,
            ContainerType="CMAF",
            HlsManifests=[{"ManifestName": "index"}],
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        "Validation error encountered at request.containerType: You can't change the container type after you"
        " create an origin endpoint. To use a different container type, you'll need to create a new origin endpoint"
    ), f"unexpected ValidationException message: {message!r}"
    reason = response.get("ValidationExceptionType")
    assert reason == "CONTAINER_TYPE_IMMUTABLE", f"expected ValidationExceptionType CONTAINER_TYPE_IMMUTABLE, got {reason!r}"

    # Effect absent: ContainerType and ETag are unchanged by the rejected mutation.
    unchanged = mp.get_origin_endpoint(
        ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name
    )
    assert unchanged["ContainerType"] == "TS", f"expected ContainerType TS, got {unchanged['ContainerType']!r}"
    assert unchanged["ETag"] == etag, f"expected ETag unchanged at {etag!r}, got {unchanged['ETag']!r}"

    # Positive control: an update that keeps ContainerType the same, but changes Description, succeeds.
    updated = mp.update_origin_endpoint(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=endpoint_name,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index"}],
        Description="updated-description",
    )
    assert updated["ContainerType"] == "TS", f"expected ContainerType TS, got {updated['ContainerType']!r}"
    assert updated["Description"] == "updated-description", f"expected updated description, got {updated['Description']!r}"
    assert updated["ETag"] != unchanged["ETag"], "expected ETag to change after a successful update"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
