"""start-viewer-session-revocation-ignores-broadcast-state."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-viewer-session-revocation-ignores-broadcast-state"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartViewerSessionRevocation answers 200 on a channel that never broadcast, and GetStream fails
    ChannelNotBroadcasting with the same exact message before and after it."""
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-revoke-idle-")
    arn = ivs.create_channel(name=name)["channel"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=arn))

    offline_msg = f"Channel: {arn} is not currently online"
    before = _error(lambda: ivs.get_stream(channelArn=arn))
    assert before["Code"] == "ChannelNotBroadcasting", (
        f"expected channel to have no broadcast state before revocation, got {before['Code']!r}"
    )
    assert before["Message"] == offline_msg, repr(before["Message"])

    resp = ivs.start_viewer_session_revocation(
        channelArn=arn, viewerId="sim2real-idle-viewer"
    )
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected revocation on an idle channel to succeed, got HTTP {status}"

    after = _error(lambda: ivs.get_stream(channelArn=arn))
    assert after["Code"] == "ChannelNotBroadcasting", (
        f"revocation must not change the channel's broadcast state, got {after['Code']!r}"
    )
    assert after["Message"] == offline_msg, repr(after["Message"])


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
