"""multitrack-requires-fragmented-mp4-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "multitrack-requires-fragmented-mp4-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs"]


def _error(fn):
    """Call fn(); return its botocore error (Code and Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChannel rejects multitrackInputConfiguration.enabled=true combined with
    containerFormat=TS (multitrack requires FRAGMENTED_MP4), and creates no channel;
    the identical request with containerFormat=FRAGMENTED_MP4 succeeds."""
    ivs = ctx.client("ivs")
    multitrack = {
        "enabled": True,
        "policy": "ALLOW",
        "maximumResolution": "HD",
    }

    bad_name = ctx.unique_name("sim2real-ivs-mt-bad-")
    error = _error(
        lambda: ivs.create_channel(
            name=bad_name,
            multitrackInputConfiguration=multitrack,
            containerFormat="TS",
        )
    )
    assert error["Code"] == "ValidationException", (
        f"multitrack enabled + containerFormat=TS was rejected with {error['Code']!r}, expected "
        f"'ValidationException'"
    )
    assert error["Message"] == (
        "Request member: multitrack_input_configuration.enabled failed to satisfy the "
        "constraints: invalid value for multitrack input configuration enabled and container format"
    ), repr(error["Message"])

    # Effect absent: no channel with the rejected name was created.
    found = [c for c in ivs.list_channels(filterByName=bad_name)["channels"]]
    assert found == [], f"a channel was created despite the rejected request: {found!r}"

    # Positive control: same multitrack config with the required container format.
    good_name = ctx.unique_name("sim2real-ivs-mt-good-")
    created = ivs.create_channel(
        name=good_name,
        multitrackInputConfiguration=multitrack,
        containerFormat="FRAGMENTED_MP4",
        tags={"purpose": "sim2real"},
    )["channel"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=created["arn"]))

    # Independent read at the destination, not the mutating call's own response.
    got = ivs.get_channel(arn=created["arn"])["channel"]
    assert got["containerFormat"] == "FRAGMENTED_MP4", (
        f"GetChannel reported containerFormat={got['containerFormat']!r}, expected "
        f"'FRAGMENTED_MP4'"
    )
    assert got["multitrackInputConfiguration"]["enabled"] is True, (
        f"GetChannel reported multitrackInputConfiguration.enabled="
        f"{got['multitrackInputConfiguration']['enabled']!r}, expected True"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
