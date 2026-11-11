"""channel-multitrack-configuration-persisted."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "channel-multitrack-configuration-persisted"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A STANDARD channel created with multitrack input enabled and a compatible
    FRAGMENTED_MP4 container format persists both fields exactly as set."""
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-multitrack-")
    resp = ivs.create_channel(
        name=name,
        type="STANDARD",
        multitrackInputConfiguration={
            "enabled": True,
            "policy": "ALLOW",
            "maximumResolution": "HD",
        },
        containerFormat="FRAGMENTED_MP4",
    )
    channel = resp["channel"]
    arn = channel["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=arn))

    created_mtc = channel["multitrackInputConfiguration"]
    assert created_mtc["enabled"] is True, f"expected enabled=True, got {created_mtc}"
    assert created_mtc["policy"] == "ALLOW", f"expected policy=ALLOW, got {created_mtc}"
    assert created_mtc["maximumResolution"] == "HD", f"expected maximumResolution=HD, got {created_mtc}"
    assert channel["containerFormat"] == "FRAGMENTED_MP4", (
        f"expected containerFormat=FRAGMENTED_MP4 on create response, got {channel['containerFormat']!r}"
    )

    got = ivs.get_channel(arn=arn)["channel"]
    assert got["type"] == "STANDARD", f"expected type=STANDARD to persist, got {got['type']!r}"
    mtc = got["multitrackInputConfiguration"]
    assert mtc["enabled"] is True, f"expected enabled=True on independent read, got {mtc}"
    assert mtc["policy"] == "ALLOW", f"expected policy=ALLOW on independent read, got {mtc}"
    assert mtc["maximumResolution"] == "HD", f"expected maximumResolution=HD on independent read, got {mtc}"
    assert got["containerFormat"] == "FRAGMENTED_MP4", (
        f"expected containerFormat=FRAGMENTED_MP4 on independent read, got {got['containerFormat']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
