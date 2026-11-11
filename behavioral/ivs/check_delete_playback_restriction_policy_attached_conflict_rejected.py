"""delete-playback-restriction-policy-attached-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-playback-restriction-policy-attached-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePlaybackRestrictionPolicy on a policy a channel references fails ConflictException with the exact
    message and it stays; an unattached policy deletes, and after the channel is removed this one deletes too."""
    ivs = ctx.client("ivs")

    # positive control: an unattached policy deletes cleanly, before anything is broken
    control_arn = ivs.create_playback_restriction_policy(
        name=ctx.unique_name("sim2real-ivs-policy-unattached-"),
        allowedCountries=["US"],
        allowedOrigins=[],
    )["playbackRestrictionPolicy"]["arn"]
    ctx.on_cleanup(lambda: _safe_delete_policy(ivs, control_arn))
    ivs.delete_playback_restriction_policy(arn=control_arn)
    control_error = _client_error(lambda: ivs.get_playback_restriction_policy(arn=control_arn))
    assert control_error["Code"] == "ResourceNotFoundException", (
        f"expected the unattached control policy to read back ResourceNotFoundException after "
        f"delete, got {control_error!r}"
    )
    assert control_error["Message"] == f"Resource: {control_arn} not found", (
        f"unexpected GetPlaybackRestrictionPolicy not-found message: {control_error['Message']!r}"
    )

    arn1 = ivs.create_playback_restriction_policy(
        name=ctx.unique_name("sim2real-ivs-policy-attached-"),
        allowedCountries=["US"],
        allowedOrigins=[],
    )["playbackRestrictionPolicy"]["arn"]
    ctx.on_cleanup(lambda: _safe_delete_policy(ivs, arn1))

    channel_arn = ivs.create_channel(
        name=ctx.unique_name("sim2real-ivs-chan-"), playbackRestrictionPolicyArn=arn1
    )["channel"]["arn"]
    ctx.on_cleanup(lambda: _safe_delete_channel(ivs, channel_arn))

    error = _client_error(lambda: ivs.delete_playback_restriction_policy(arn=arn1))
    assert error["Code"] == "ConflictException", (
        f"expected ConflictException deleting a policy still attached to a channel, got {error!r}"
    )
    assert error["Message"] == (
        f"Unable to perform ivs:DeletePlaybackRestrictionPolicy while {arn1} "
        f"is still attached to a channel"
    ), f"unexpected DeletePlaybackRestrictionPolicy conflict message: {error['Message']!r}"

    # effect absent: the attached policy still exists
    still_arn = ivs.get_playback_restriction_policy(arn=arn1)["playbackRestrictionPolicy"]["arn"]
    assert still_arn == arn1, f"expected the rejected delete to leave {arn1!r} in place, got {still_arn!r}"

    # restore: detach by deleting the referencing channel
    ivs.delete_channel(arn=channel_arn)

    # identical call now succeeds, and an independent read proves it
    ivs.delete_playback_restriction_policy(arn=arn1)
    error_after = _client_error(lambda: ivs.get_playback_restriction_policy(arn=arn1))
    assert error_after["Code"] == "ResourceNotFoundException", (
        f"expected {arn1!r} to read back ResourceNotFoundException once no channel references it "
        f"and the identical delete call has succeeded, got {error_after!r}"
    )
    assert error_after["Message"] == f"Resource: {arn1} not found", (
        f"unexpected GetPlaybackRestrictionPolicy not-found message: {error_after['Message']!r}"
    )


def _client_error(fn):
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it succeeded and returned {result!r}")


def _safe_delete_policy(ivs, arn) -> None:
    try:
        ivs.delete_playback_restriction_policy(arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_channel(ivs, arn) -> None:
    try:
        ivs.delete_channel(arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
