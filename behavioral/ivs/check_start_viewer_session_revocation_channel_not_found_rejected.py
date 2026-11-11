"""start-viewer-session-revocation-channel-not-found-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "start-viewer-session-revocation-channel-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["ivs"]


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartViewerSessionRevocation rejects a well-formed but nonexistent
    channelArn with ResourceNotFoundException, while the identical call against a
    real channel succeeds."""
    ivs = ctx.client("ivs")

    ghost_name = ctx.unique_name("sim2real-ivs-svr-ghost-")
    ghost_arn = ivs.create_channel(name=ghost_name, tags={"purpose": "sim2real"})[
        "channel"
    ]["arn"]
    ivs.delete_channel(arn=ghost_arn)

    error = _error(
        lambda: ivs.start_viewer_session_revocation(
            channelArn=ghost_arn, viewerId="viewer-1"
        )
    )
    assert error["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a deleted channel, got {error['Code']!r}"
    )
    assert error["Message"] == f"Resource: {ghost_arn} not found", repr(error["Message"])

    # Positive control: a real channel accepts the same call without error.
    live_name = ctx.unique_name("sim2real-ivs-svr-live-")
    live_arn = ivs.create_channel(name=live_name, tags={"purpose": "sim2real"})[
        "channel"
    ]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=live_arn))

    resp = ivs.start_viewer_session_revocation(channelArn=live_arn, viewerId="viewer-1")
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected the identical call against a live channel to succeed, got HTTP {status}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
