"""update-channel-stale-etag-rejected."""
from __future__ import annotations

from typing import Any, Callable, Optional

from behavioral_harness import tags

CHECK = "update-channel-stale-etag-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackagev2"]

STALE_ETAG = (
    "You’ve specified an entity tag with your request that does not match the resource’s "
    "current entity tag. This can occur if the resource has been updated by another request "
    "between the time you retrieved the ETag and when you made your update request"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateChannel with an ETag from before the last update fails ConflictException with the exact
    message and leaves Description 'v2' and the current ETag in place, while the same update with the
    current ETag sets 'v3', as GetChannel confirms."""
    mp = ctx.client("mediapackagev2")

    group_name = ctx.unique_name("sim2real-mpv2-cg-")
    mp.create_channel_group(ChannelGroupName=group_name, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))

    channel_name = ctx.unique_name("sim2real-mpv2-ch-")
    created = mp.create_channel(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        Description="v1",
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(
        lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    )
    stale_etag = created["ETag"]

    updated = mp.update_channel(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        Description="v2",
        ETag=stale_etag,
    )
    fresh_etag = updated["ETag"]
    assert fresh_etag != stale_etag, f"ETag did not change after update: {fresh_etag!r}"

    # break: reuse the stale ETag from before the v1->v2 update
    err = _client_error(
        lambda: mp.update_channel(
            ChannelGroupName=group_name,
            ChannelName=channel_name,
            Description="v3",
            ETag=stale_etag,
        )
    )
    assert err is not None, "expected a stale ETag update to be rejected"
    code = err.response["Error"]["Code"]
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    message = err.response["Error"]["Message"]
    assert message == STALE_ETAG, f"expected message {STALE_ETAG!r}, got {message!r}"

    # effect absent: Description is still "v2", not "v3"
    still = mp.get_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    assert still["Description"] == "v2", f"unexpected Description {still['Description']!r}"
    assert still["ETag"] == fresh_etag, f"ETag drifted despite rejected update: {still['ETag']!r}"

    # positive control: updating with the correct current ETag succeeds
    final = mp.update_channel(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        Description="v3",
        ETag=fresh_etag,
    )
    assert final["Description"] == "v3", f"unexpected Description {final['Description']!r}"

    # terminal read: independent GetChannel at the destination, not the mutating
    # call's own response
    confirmed = mp.get_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    assert confirmed["Description"] == "v3", (
        f"GetChannel did not reflect the successful update: {confirmed['Description']!r}"
    )
    assert confirmed["ETag"] == final["ETag"], (
        f"GetChannel ETag {confirmed['ETag']!r} != update response ETag {final['ETag']!r}"
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
