"""update-channel-group-stale-etag-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-channel-group-stale-etag-conflict-rejected"
GROUP = "error-semantics"
SERVICES = ["mediapackagev2"]

STALE_ETAG = (
    "You’ve specified an entity tag with your request that does not match the resource’s "
    "current entity tag. This can occur if the resource has been updated by another request "
    "between the time you retrieved the ETag and when you made your update request"
)


def _client_error(fn):
    """Call fn(); return its ClientError. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e
    raise AssertionError(
        f"real AWS rejects this stale-ETag update, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateChannelGroup with a stale x-amzn-update-if-match ETag is rejected with
    ConflictException, the description from the intervening successful update is
    preserved, and updating again with the current ETag succeeds (positive control)."""
    mp = ctx.client("mediapackagev2")
    group = ctx.unique_name("sim2real-mpkg-cg-")
    created = mp.create_channel_group(
        ChannelGroupName=group, Description="v0", Tags={"sim2real": "stale-etag-conflict"}
    )
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group))
    stale_etag = created["ETag"]

    updated = mp.update_channel_group(
        ChannelGroupName=group, ETag=stale_etag, Description="v1"
    )
    current_etag = updated["ETag"]
    assert current_etag != stale_etag, (
        f"ETag did not rotate after a successful update: still {current_etag!r}"
    )

    err = _client_error(
        lambda: mp.update_channel_group(
            ChannelGroupName=group, ETag=stale_etag, Description="v2-should-not-apply"
        )
    )
    code = err.response["Error"]["Code"]
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    message = err.response["Error"]["Message"]
    assert message == STALE_ETAG, f"expected message {STALE_ETAG!r}, got {message!r}"

    # Effect absent: the stale update did not overwrite the successful "v1" update.
    got = mp.get_channel_group(ChannelGroupName=group)
    assert got["Description"] == "v1", f"expected Description 'v1', got {got['Description']!r}"
    assert got["ETag"] == current_etag, f"expected ETag {current_etag!r}, got {got['ETag']!r}"

    # Positive control: updating with the current ETag succeeds.
    final = mp.update_channel_group(
        ChannelGroupName=group, ETag=current_etag, Description="v3"
    )
    assert final["Description"] == "v3", f"expected Description 'v3', got {final['Description']!r}"
    final_desc = mp.get_channel_group(ChannelGroupName=group)["Description"]
    assert final_desc == "v3", f"expected Description 'v3' on read-back, got {final_desc!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
