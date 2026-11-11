"""enabled-controls-list-get-consistency."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "enabled-controls-list-get-consistency"
GROUP = "state"
SERVICES = ["controltower"]

NO_LANDING_ZONE_MESSAGE = (
    "AWS Control Tower cannot complete the operation, because you must create a landing "
    "zone first. To continue, create your landing zone from the console, or call the "
    "CreateLandingZone API."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Each ListEnabledControls entry is readable via GetEnabledControl with the same arn, controlIdentifier
    and targetIdentifier; with no landing zone, ListEnabledControls fails with ResourceNotFoundException
    and the "create a landing zone first" message."""
    ct = ctx.client("controltower")

    landing_zones = ct.list_landing_zones(maxResults=1)["landingZones"]
    if not landing_zones:
        code, message = _error(lambda: ct.list_enabled_controls(maxResults=20))
        assert code == "ResourceNotFoundException", (
            f"expected a controlled precondition error for ListEnabledControls with no "
            f"landing zone present, got {code}"
        )
        assert message == NO_LANDING_ZONE_MESSAGE, (
            f"expected the no-landing-zone message for ListEnabledControls, got {message!r}"
        )
        return

    entries = ct.list_enabled_controls(maxResults=20)["enabledControls"]
    if not entries:
        return  # landing zone exists but nothing enabled; nothing further to cross-check

    for summary in entries[:5]:  # bound the number of cross-checks
        detail = ct.get_enabled_control(enabledControlIdentifier=summary["arn"])["enabledControlDetails"]
        assert detail["arn"] == summary["arn"], (
            f"GetEnabledControl arn {detail['arn']!r} disagrees with the ListEnabledControls "
            f"summary arn {summary['arn']!r} for the same control"
        )
        assert detail["controlIdentifier"] == summary["controlIdentifier"], (
            f"GetEnabledControl controlIdentifier {detail['controlIdentifier']!r} disagrees with "
            f"the ListEnabledControls summary controlIdentifier {summary['controlIdentifier']!r}"
        )
        assert detail["targetIdentifier"] == summary["targetIdentifier"], (
            f"GetEnabledControl targetIdentifier {detail['targetIdentifier']!r} disagrees with "
            f"the ListEnabledControls summary targetIdentifier {summary['targetIdentifier']!r}"
        )
        assert detail["statusSummary"]["status"] in ("SUCCEEDED", "FAILED", "UNDER_CHANGE"), (
            f"GetEnabledControl returned an unmodelled statusSummary.status "
            f"{detail['statusSummary']['status']!r} for {summary['arn']!r}"
        )


def _error(fn):
    """``(code, message)`` of the rejection ``fn`` raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected ListEnabledControls to reject with no landing zone present, but it "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

