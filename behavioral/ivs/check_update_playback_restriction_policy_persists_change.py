"""update-playback-restriction-policy-persists-change."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-playback-restriction-policy-persists-change"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePlaybackRestrictionPolicy's new allowedCountries value is durably reflected by a
    subsequent GetPlaybackRestrictionPolicy."""
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-policy-")
    arn = ivs.create_playback_restriction_policy(
        name=name, allowedCountries=["US"], allowedOrigins=[], tags={"purpose": "sim2real"}
    )["playbackRestrictionPolicy"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_playback_restriction_policy(arn=arn))

    ivs.update_playback_restriction_policy(arn=arn, allowedCountries=["FR", "DE"], allowedOrigins=[])
    got = ivs.get_playback_restriction_policy(arn=arn)["playbackRestrictionPolicy"]
    assert sorted(got["allowedCountries"]) == ["DE", "FR"], (
        f"expected allowedCountries ['DE', 'FR'] after update, got {got['allowedCountries']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
