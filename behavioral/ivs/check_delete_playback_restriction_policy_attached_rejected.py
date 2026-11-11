"""delete-playback-restriction-policy-attached-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-playback-restriction-policy-attached-rejected"
GROUP = "error-semantics"
SERVICES = ["ivs"]


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePlaybackRestrictionPolicy fails ConflictException with the exact message while a channel is attached
    and the policy survives; after the channel is deleted it deletes, then reads and updates fail not-found."""
    ivs = ctx.client("ivs")
    policy_name = ctx.unique_name("sim2real-ivs-prp-")
    policy = ivs.create_playback_restriction_policy(
        name=policy_name,
        allowedCountries=["US"],
        allowedOrigins=["https://example.com"],
        tags={"purpose": "sim2real"},
    )["playbackRestrictionPolicy"]
    policy_arn = policy["arn"]

    chan_name = ctx.unique_name("sim2real-ivs-prp-chan-")
    channel = ivs.create_channel(
        name=chan_name,
        playbackRestrictionPolicyArn=policy_arn,
        tags={"purpose": "sim2real"},
    )["channel"]
    chan_arn = channel["arn"]
    ctx.on_cleanup(lambda: _safe_delete(ivs.delete_channel, arn=chan_arn))
    ctx.on_cleanup(
        lambda: _safe_delete(ivs.delete_playback_restriction_policy, arn=policy_arn)
    )

    error = _client_error(lambda: ivs.delete_playback_restriction_policy(arn=policy_arn))
    assert error["Code"] == "ConflictException", f"expected ConflictException while attached, got {error!r}"
    assert error["Message"] == (
        f"Unable to perform ivs:DeletePlaybackRestrictionPolicy while {policy_arn} "
        f"is still attached to a channel"
    ), f"unexpected DeletePlaybackRestrictionPolicy conflict message: {error['Message']!r}"

    still_there = ivs.get_playback_restriction_policy(arn=policy_arn)[
        "playbackRestrictionPolicy"
    ]
    assert still_there["arn"] == policy_arn, (
        f"policy {policy_arn} should have survived the rejected delete, got {still_there!r}"
    )

    # Positive control: detach then delete succeeds.
    ivs.delete_channel(arn=chan_arn)
    ivs.delete_playback_restriction_policy(arn=policy_arn)
    after = _client_error(
        lambda: ivs.get_playback_restriction_policy(arn=policy_arn)
    )
    assert after["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading a deleted policy, got {after!r}"
    )
    assert after["Message"] == f"Resource: {policy_arn} not found", (
        f"unexpected GetPlaybackRestrictionPolicy not-found message: {after['Message']!r}"
    )

    # A mutation on the dead id also fails: gone means unusable, not just unreadable.
    update_error = _client_error(
        lambda: ivs.update_playback_restriction_policy(arn=policy_arn, allowedCountries=["CA"])
    )
    assert update_error["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException updating a deleted policy, got {update_error!r}"
    )
    assert update_error["Message"] == f"Resource: {policy_arn} not found", (
        f"unexpected UpdatePlaybackRestrictionPolicy not-found message: {update_error['Message']!r}"
    )


def _safe_delete(fn, **kwargs) -> None:
    from botocore.exceptions import ClientError

    try:
        fn(**kwargs)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
