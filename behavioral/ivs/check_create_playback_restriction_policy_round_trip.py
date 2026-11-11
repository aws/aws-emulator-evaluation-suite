"""create-playback-restriction-policy-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-playback-restriction-policy-round-trip"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePlaybackRestrictionPolicy persists allowedCountries/allowedOrigins/
    enableStrictOriginEnforcement exactly as given, and GetPlaybackRestrictionPolicy returns
    the same values."""
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-policy-")
    resp = ivs.create_playback_restriction_policy(
        name=name,
        allowedCountries=["US", "CA"],
        allowedOrigins=["https://example.com"],
        enableStrictOriginEnforcement=True,
        tags={"sim2real-check": CHECK},
    )
    arn = resp["playbackRestrictionPolicy"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_playback_restriction_policy(arn=arn))

    created = resp["playbackRestrictionPolicy"]
    assert sorted(created["allowedCountries"]) == ["CA", "US"], (
        f"expected allowedCountries ['CA', 'US'], got {sorted(created['allowedCountries'])}"
    )
    assert created["allowedOrigins"] == ["https://example.com"], (
        f"expected allowedOrigins ['https://example.com'], got {created['allowedOrigins']}"
    )
    assert created["enableStrictOriginEnforcement"] is True, (
        f"expected enableStrictOriginEnforcement True, got {created['enableStrictOriginEnforcement']}"
    )

    got = ivs.get_playback_restriction_policy(arn=arn)["playbackRestrictionPolicy"]
    assert sorted(got["allowedCountries"]) == ["CA", "US"], (
        f"expected GetPlaybackRestrictionPolicy allowedCountries ['CA', 'US'], got {sorted(got['allowedCountries'])}"
    )
    assert got["allowedOrigins"] == ["https://example.com"], (
        f"expected GetPlaybackRestrictionPolicy allowedOrigins ['https://example.com'], got {got['allowedOrigins']}"
    )
    assert got["enableStrictOriginEnforcement"] is True, (
        f"expected GetPlaybackRestrictionPolicy enableStrictOriginEnforcement True, got {got['enableStrictOriginEnforcement']}"
    )
    assert got["name"] == name, f"expected name {name!r}, got {got['name']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
