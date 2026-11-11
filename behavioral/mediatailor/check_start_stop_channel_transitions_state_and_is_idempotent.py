"""start-stop-channel-transitions-state-and-is-idempotent."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-stop-channel-transitions-state-and-is-idempotent"
GROUP = 'channel-lifecycle'
SERVICES = ['mediatailor']


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartChannel/StopChannel drive ChannelState between STOPPED and RUNNING, and calling
    either again while already in that state is a no-op rather than an error."""
    mt = ctx.client("mediatailor")
    name = ctx.unique_name("sim2real-behav-mt-ch-")

    mt.create_channel(
        ChannelName=name,
        Outputs=[{"ManifestName": "default", "SourceGroup": "default",
                  "HlsPlaylistSettings": {"ManifestWindowSeconds": 30}}],
        PlaybackMode="LOOP",
    )
    ctx.on_cleanup(_teardown(lambda: mt.delete_channel(ChannelName=name)))

    initial = mt.describe_channel(ChannelName=name)["ChannelState"]
    assert initial == "STOPPED", f"a freshly created channel was {initial!r}, expected STOPPED"

    mt.start_channel(ChannelName=name)
    running = mt.describe_channel(ChannelName=name)["ChannelState"]
    assert running == "RUNNING", f"after StartChannel, state was {running!r}, expected RUNNING"

    # Starting an already-running channel must not fail or change the state.
    mt.start_channel(ChannelName=name)
    still_running = mt.describe_channel(ChannelName=name)["ChannelState"]
    assert still_running == "RUNNING", (
        f"a second StartChannel changed state to {still_running!r}, expected it to stay RUNNING"
    )

    mt.stop_channel(ChannelName=name)
    stopped = mt.describe_channel(ChannelName=name)["ChannelState"]
    assert stopped == "STOPPED", f"after StopChannel, state was {stopped!r}, expected STOPPED"

    # Stopping an already-stopped channel must not fail or change the state.
    mt.stop_channel(ChannelName=name)
    still_stopped = mt.describe_channel(ChannelName=name)["ChannelState"]
    assert still_stopped == "STOPPED", (
        f"a second StopChannel changed state to {still_stopped!r}, expected it to stay STOPPED"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
