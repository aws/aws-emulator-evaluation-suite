"""start-viewer-session-revocation-resource-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "start-viewer-session-revocation-resource-not-found"
GROUP = "errors"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartViewerSessionRevocation on a missing channelArn fails ResourceNotFoundException with the exact message,
    while the same call on a real channel answers 200."""
    ivs = ctx.client("ivs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = f"arn:aws:ivs:{ctx.region}:{account}:channel/does-not-exist-0000002"

    error = _error(
        lambda: ivs.start_viewer_session_revocation(channelArn=bogus_arn, viewerId="viewer-1")
    )
    assert error["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent channelArn, got {error['Code']!r}"
    )
    assert error["Message"] == f"Resource: {bogus_arn} not found", repr(error["Message"])

    # Positive control: the identical call against a real channel succeeds, so the
    # rejection above is specific to the nonexistent channel and not a blanket failure.
    live_name = ctx.unique_name("sim2real-ivs-svr-live-")
    live_arn = ivs.create_channel(name=live_name, tags={"purpose": "sim2real"})["channel"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=live_arn))

    resp = ivs.start_viewer_session_revocation(channelArn=live_arn, viewerId="viewer-1")
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected 200 for the identical call against a real channel, got {status}"


def _error(fn):
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
