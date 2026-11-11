"""create-channel-duplicate-name-rejected-without-mutating-existing."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-channel-duplicate-name-rejected-without-mutating-existing"
GROUP = 'channel-lifecycle'
SERVICES = ['mediatailor']


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-creating a channel under a name already in use is refused, and the attempt — with
    a different Outputs than the original — leaves the existing channel untouched."""
    mt = ctx.client("mediatailor")
    name = ctx.unique_name("sim2real-behav-mt-ch-")

    mt.create_channel(
        ChannelName=name,
        Outputs=[{"ManifestName": "default", "SourceGroup": "default",
                  "HlsPlaylistSettings": {"ManifestWindowSeconds": 30}}],
        PlaybackMode="LOOP",
        Tier="BASIC",
    )
    ctx.on_cleanup(_teardown(lambda: mt.delete_channel(ChannelName=name)))

    code, message = _error(lambda: mt.create_channel(
        ChannelName=name,
        Outputs=[{"ManifestName": "other", "SourceGroup": "other",
                  "HlsPlaylistSettings": {"ManifestWindowSeconds": 60}}],
        PlaybackMode="LOOP",
        Tier="BASIC",
    ))
    assert code == "BadRequestException", f"expected BadRequestException, got {code}: {message!r}"
    assert message == (
        "This channel already exists. Create a unique channel and resubmit your request."
    ), f"unexpected message {message!r}"

    current = mt.describe_channel(ChannelName=name)
    assert current["PlaybackMode"] == "LOOP", (
        f"the rejected duplicate create changed PlaybackMode to {current['PlaybackMode']!r}"
    )
    assert current["Tier"] == "BASIC", (
        f"the rejected duplicate create changed Tier to {current['Tier']!r}"
    )
    assert current["Outputs"][0]["ManifestName"] == "default", (
        f"the rejected duplicate create changed Outputs to {current['Outputs']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
