"""get-landing-zone-nonexistent-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-landing-zone-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["controltower"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetLandingZone on a well-formed unknown landing zone ARN fails with ResourceNotFoundException (with no
    landing zone, the exact "could not find a landing zone identifier" message), while an existing
    landing zone's listed ARN reads back."""
    ct = ctx.client("controltower")

    existing = ct.list_landing_zones()["landingZones"]
    if existing:
        real_arn = existing[0]["arn"]
        detail = ct.get_landing_zone(landingZoneIdentifier=real_arn)["landingZone"]
        assert detail["arn"] == real_arn, (
            f"positive control failed: GetLandingZone on a real, listed landing zone "
            f"ARN did not return that ARN, got {detail.get('arn')!r}"
        )

    fake_arn = (
        "arn:aws:controltower:"
        f"{ctx.region}:{_account_id(ctx)}:landingzone/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    )
    code, message = _error(lambda: ct.get_landing_zone(landingZoneIdentifier=fake_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    if not existing:
        expected = (
            "AWS Control Tower could not find a landing zone identifier value for the "
            f"management account: {_account_id(ctx)}, in Region {ctx.region}. To continue, "
            "provide a valid resource ARN or landingZoneIdentifier string for your landing zone."
        )
        assert message == expected, f"expected {expected!r}, got {message!r}"
    # message varies: the fake-ARN text with a landing zone present is undocumented, so only the
    # no-landing-zone message is asserted.


def _error(fn):
    """``(code, message)`` of the rejection ``fn`` raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
