"""delete-channel-is-idempotent-and-removes-resource-for-dependent-ops."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-channel-is-idempotent-and-removes-resource-for-dependent-ops"
GROUP = 'channel-lifecycle'
SERVICES = ['mediatailor']


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a channel is itself idempotent, and once gone every operation that names
    the channel refuses with the same NotFoundException rather than some reaching stale state."""
    mt = ctx.client("mediatailor")
    name = ctx.unique_name("sim2real-behav-mt-ch-")
    arn = f"arn:aws:mediatailor:{ctx.region}:{ctx.account}:channel/{name}"

    mt.create_channel(
        ChannelName=name,
        Outputs=[{"ManifestName": "default", "SourceGroup": "default",
                  "HlsPlaylistSettings": {"ManifestWindowSeconds": 30}}],
        PlaybackMode="LOOP",
    )

    mt.delete_channel(ChannelName=name)

    # A second delete of an already-gone channel is a no-op, not an error.
    mt.delete_channel(ChannelName=name)

    code, message = _error(lambda: mt.describe_channel(ChannelName=name))
    assert code == "NotFoundException", f"DescribeChannel on deleted channel gave {code}: {message!r}"
    assert message == "The specified channel doesn't exist.", f"unexpected message {message!r}"

    code, message = _error(lambda: mt.get_channel_schedule(ChannelName=name))
    assert code == "NotFoundException", f"GetChannelSchedule on deleted channel gave {code}: {message!r}"
    assert message == "The specified channel doesn't exist.", f"unexpected message {message!r}"

    code, message = _error(lambda: mt.start_channel(ChannelName=name))
    assert code == "NotFoundException", f"StartChannel on deleted channel gave {code}: {message!r}"
    assert message == "The specified channel doesn't exist.", f"unexpected message {message!r}"

    code, message = _error(
        lambda: mt.configure_logs_for_channel(ChannelName=name, LogTypes=["AS_RUN"])
    )
    assert code == "NotFoundException", (
        f"ConfigureLogsForChannel on deleted channel gave {code}: {message!r}"
    )
    assert message == "The specified channel doesn't exist.", f"unexpected message {message!r}"

    code, message = _error(lambda: mt.list_alerts(ResourceArn=arn))
    assert code == "NotFoundException", f"ListAlerts on deleted channel's arn gave {code}: {message!r}"
    assert message == "The specified channel doesn't exist.", f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
