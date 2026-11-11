"""create-channel-invalid-locking-mode-combo-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-channel-invalid-locking-mode-combo-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackagev2"]


_LOCKING_MODE_NEEDS_CMAF = (
    "Validation error encountered at request.outputLockingMode: OutputLockingMode can only be "
    "configured when the channel InputType is CMAF or MULTIVIEW. To use OutputLockingMode, "
    "create a channel with CMAF or MULTIVIEW input type"
)
_CHANNEL_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your channel. "
    "Verify your channel name or add a channel and then try again"
)


def _error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChannel with InputType=HLS and an OutputLockingMode fails ValidationException with the exact
    message and creates no channel, while InputType=CMAF with OutputLockingMode=EPOCH_LOCKED is created and
    GetChannel returns both values."""
    mp = ctx.client("mediapackagev2")
    group = ctx.unique_name("sim2real-mpkg-cg-")
    mp.create_channel_group(ChannelGroupName=group, Tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group))

    bad_channel = ctx.unique_name("sim2real-mpkg-ch-bad-")
    err = _error(
        lambda: mp.create_channel(
            ChannelGroupName=group,
            ChannelName=bad_channel,
            InputType="HLS",
            OutputLockingMode="EPOCH_LOCKED",
        )
    )
    assert err["Code"] == "ValidationException", f"got {err!r}"
    assert err["Message"] == _LOCKING_MODE_NEEDS_CMAF, f"got {err!r}"

    # Effect absent: no channel was created under that name.
    err_after = _error(
        lambda: mp.get_channel(ChannelGroupName=group, ChannelName=bad_channel)
    )
    assert err_after["Code"] == "ResourceNotFoundException", f"got {err_after!r}"
    assert err_after["Message"] == _CHANNEL_NOT_FOUND, f"got {err_after!r}"

    # Positive control: the same OutputLockingMode with InputType=CMAF succeeds.
    good_channel = ctx.unique_name("sim2real-mpkg-ch-good-")
    mp.create_channel(
        ChannelGroupName=group,
        ChannelName=good_channel,
        InputType="CMAF",
        OutputLockingMode="EPOCH_LOCKED",
        Tags={"sim2real": "true"},
    )
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group, ChannelName=good_channel))

    # Terminal read: an independent GetChannel call, not the CreateChannel response itself.
    fetched = mp.get_channel(ChannelGroupName=group, ChannelName=good_channel)
    assert fetched["InputType"] == "CMAF", fetched["InputType"]
    assert fetched["OutputLockingMode"] == "EPOCH_LOCKED", fetched["OutputLockingMode"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
