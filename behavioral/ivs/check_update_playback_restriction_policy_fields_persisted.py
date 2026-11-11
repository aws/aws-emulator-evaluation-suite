"""update-playback-restriction-policy-fields-persisted."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-playback-restriction-policy-fields-persisted"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePlaybackRestrictionPolicy fully replaces allowedCountries, allowedOrigins,
    enableStrictOriginEnforcement, and name, and GetPlaybackRestrictionPolicy reflects
    exactly the updated values."""
    ivs = ctx.client("ivs")
    name1 = ctx.unique_name("sim2real-ivs-prp-")
    resp = ivs.create_playback_restriction_policy(
        name=name1,
        allowedCountries=["US"],
        allowedOrigins=["https://example.com"],
        enableStrictOriginEnforcement=False,
        tags={"purpose": "sim2real"},
    )
    arn = resp["playbackRestrictionPolicy"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_playback_restriction_policy(arn=arn))

    name2 = ctx.unique_name("sim2real-ivs-prp-upd-")
    ivs.update_playback_restriction_policy(
        arn=arn,
        name=name2,
        allowedCountries=["US", "CA"],
        allowedOrigins=["https://example.com", "https://foo.example.com"],
        enableStrictOriginEnforcement=True,
    )

    got = ivs.get_playback_restriction_policy(arn=arn)["playbackRestrictionPolicy"]
    assert got["name"] == name2, f"expected name {name2!r}, got {got['name']!r}"
    assert sorted(got["allowedCountries"]) == ["CA", "US"], (
        f"expected allowedCountries ['CA', 'US'], got {sorted(got['allowedCountries'])!r}"
    )
    assert sorted(got["allowedOrigins"]) == sorted(
        ["https://example.com", "https://foo.example.com"]
    ), f"expected allowedOrigins to be replaced, got {sorted(got['allowedOrigins'])!r}"
    assert got["enableStrictOriginEnforcement"] is True, (
        f"expected enableStrictOriginEnforcement True, got {got['enableStrictOriginEnforcement']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
