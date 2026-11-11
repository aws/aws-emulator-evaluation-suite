"""create-playback-restriction-policy-invalid-country-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-playback-restriction-policy-invalid-country-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePlaybackRestrictionPolicy with allowedCountries "ZZ" fails ValidationException with the exact message
    and creates no policy, while "US" creates one that reads back."""
    ivs = ctx.client("ivs")
    bad_name = ctx.unique_name("sim2real-ivs-policy-bad-")

    error = _client_error(
        lambda: ivs.create_playback_restriction_policy(
            name=bad_name, allowedCountries=["ZZ"], allowedOrigins=[]
        )
    )
    assert error["Code"] == "ValidationException", (
        f"expected ValidationException for allowedCountries=['ZZ'], got {error!r}"
    )
    assert error["Message"] == (
        "Request member: allowed_countries failed to satisfy the constraints: "
        "invalid argument allowed country list member"
    ), f"unexpected validation message for allowedCountries=['ZZ']: {error['Message']!r}"

    # effect absent: no policy with the rejected name was created
    names = {p["name"] for p in ivs.list_playback_restriction_policies()["playbackRestrictionPolicies"]}
    assert bad_name not in names, (
        f"expected {bad_name!r} absent from list_playback_restriction_policies, but found it"
    )

    good_name = ctx.unique_name("sim2real-ivs-policy-good-")
    arn = ivs.create_playback_restriction_policy(
        name=good_name, allowedCountries=["US"], allowedOrigins=[], tags={"purpose": "sim2real"}
    )["playbackRestrictionPolicy"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_playback_restriction_policy(arn=arn))
    got = ivs.get_playback_restriction_policy(arn=arn)["playbackRestrictionPolicy"]
    assert got["allowedCountries"] == ["US"], (
        f"expected allowedCountries=['US'] on the identical call with a real code, got {got['allowedCountries']!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(
        f"real AWS rejects allowedCountries=['ZZ'], but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
