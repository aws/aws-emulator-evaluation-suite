"""batch-start-viewer-session-revocation-per-item-errors."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-start-viewer-session-revocation-per-item-errors"
GROUP = "data-plane"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchStartViewerSessionRevocation reports per-item failures in the `errors`
    list rather than raising a top-level exception for the whole batch: a valid
    channel/viewer entry produces no error while a non-existent-channel entry does."""
    ivs = ctx.client("ivs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-ivs-revoke-")
    real_arn = ivs.create_channel(name=name, tags={"purpose": "sim2real"})["channel"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=real_arn))

    bogus_arn = f"arn:aws:ivs:{ctx.region}:{account_id}:channel/sim2real0missing01"

    resp = ivs.batch_start_viewer_session_revocation(
        viewerSessions=[
            {"channelArn": real_arn, "viewerId": "sim2real-viewer-ok"},
            {"channelArn": bogus_arn, "viewerId": "sim2real-viewer-bad"},
        ]
    )

    errors = resp.get("errors", [])
    assert len(errors) == 1, f"expected exactly 1 per-item error, got {len(errors)}: {errors!r}"
    assert errors[0]["channelArn"] == bogus_arn, (
        f"expected the error entry to name the bogus channel {bogus_arn!r}, "
        f"got {errors[0].get('channelArn')!r}"
    )
    assert errors[0]["viewerId"] == "sim2real-viewer-bad", (
        f"expected the error entry to name the bad viewerId, got {errors[0].get('viewerId')!r}"
    )
    assert errors[0]["code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the nonexistent channel, "
        f"got {errors[0].get('code')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
