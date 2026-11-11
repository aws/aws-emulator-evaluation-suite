"""playback-restriction-policy-update-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "playback-restriction-policy-update-persists"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePlaybackRestrictionPolicy replaces the allowed-countries list and the change is
    durable across an independent Get call."""
    ivs = ctx.client("ivs")
    created = ivs.create_playback_restriction_policy(
        name=ctx.unique_name("sim2real-ivs-prp-"),
        allowedCountries=["US", "CA"],
        enableStrictOriginEnforcement=False,
        tags={"purpose": "sim2real"},
    )["playbackRestrictionPolicy"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: ivs.delete_playback_restriction_policy(arn=arn))
    assert sorted(created["allowedCountries"]) == [
        "CA",
        "US",
    ], f"expected [CA, US] on create, got {sorted(created['allowedCountries'])}"

    updated = ivs.update_playback_restriction_policy(
        arn=arn, allowedCountries=["FR", "DE", "JP"]
    )["playbackRestrictionPolicy"]
    assert sorted(updated["allowedCountries"]) == [
        "DE",
        "FR",
        "JP",
    ], f"expected [DE, FR, JP] on the update response, got {sorted(updated['allowedCountries'])}"

    refetched = ivs.get_playback_restriction_policy(arn=arn)["playbackRestrictionPolicy"]
    assert sorted(refetched["allowedCountries"]) == [
        "DE",
        "FR",
        "JP",
    ], f"expected [DE, FR, JP] on independent re-fetch, got {sorted(refetched['allowedCountries'])}"
    # The old countries must actually be gone, not merged/appended.
    assert (
        "US" not in refetched["allowedCountries"]
    ), f"stale country US survived the update: {refetched['allowedCountries']}"
    assert (
        "CA" not in refetched["allowedCountries"]
    ), f"stale country CA survived the update: {refetched['allowedCountries']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
