"""enabled-baselines-list-get-consistency."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "enabled-baselines-list-get-consistency"
GROUP = "state"
SERVICES = ["controltower"]

NO_ADMIN_ROLE_MESSAGE = (
    "AWS Control Tower could not complete the operation because it could not assume the "
    "'AWSControlTowerAdmin' role. Check the configuration for this role and try again."
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Each ListEnabledBaselines entry is readable via GetEnabledBaseline with the same arn,
    baselineIdentifier and targetIdentifier; with no landing zone, ListEnabledBaselines fails with
    ValidationException and the AWSControlTowerAdmin role message."""
    ct = ctx.client("controltower")

    landing_zones = ct.list_landing_zones(maxResults=1)["landingZones"]
    if not landing_zones:
        code, message = _error(lambda: ct.list_enabled_baselines(maxResults=20))
        assert code == "ValidationException", (
            f"expected a controlled precondition error for ListEnabledBaselines with no "
            f"landing zone present, got {code}"
        )
        assert message == NO_ADMIN_ROLE_MESSAGE, (
            f"expected the AWSControlTowerAdmin role message for ListEnabledBaselines with "
            f"no landing zone present, got {message!r}"
        )
        return

    entries = ct.list_enabled_baselines(maxResults=20)["enabledBaselines"]
    if not entries:
        return  # landing zone exists but nothing enabled; nothing further to cross-check

    for summary in entries[:5]:  # bound the number of cross-checks
        detail = ct.get_enabled_baseline(enabledBaselineIdentifier=summary["arn"])["enabledBaselineDetails"]
        assert detail["arn"] == summary["arn"], (
            f"GetEnabledBaseline arn {detail['arn']!r} disagrees with the ListEnabledBaselines "
            f"summary arn {summary['arn']!r}"
        )
        assert detail["baselineIdentifier"] == summary["baselineIdentifier"], (
            f"GetEnabledBaseline baselineIdentifier {detail['baselineIdentifier']!r} disagrees "
            f"with the list summary {summary['baselineIdentifier']!r}"
        )
        assert detail["targetIdentifier"] == summary["targetIdentifier"], (
            f"GetEnabledBaseline targetIdentifier {detail['targetIdentifier']!r} disagrees with "
            f"the list summary {summary['targetIdentifier']!r}"
        )
        assert detail["statusSummary"]["status"] in ("SUCCEEDED", "FAILED", "UNDER_CHANGE"), (
            f"unexpected EnabledBaselineStatus {detail['statusSummary']['status']!r}"
        )


def _error(fn):
    """``(code, message)`` of the rejection ``fn`` raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected ListEnabledBaselines to reject with no landing zone present, but it "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

