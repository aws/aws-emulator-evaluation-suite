"""filter-finding-criteria-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "filter-finding-criteria-round-trip"
GROUP = "representation"
SERVICES = ["guardduty"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-gd-filter-"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """A Filter created with nested numeric range (severity) and timestamp (updatedAt)
    FindingCriteria round-trips through GetFilter/UpdateFilter with byte-exact values --
    no coercion (e.g. int->float) or truncation of the nested Condition operators."""
    gd = ctx.client("guardduty")

    detector_id = _ensure_detector(ctx, gd)

    ts_gt = 1577836800000  # 2020-01-01T00:00:00.000Z in epoch ms
    ts_lt = 1893456000000  # 2030-01-01T00:00:00.000Z in epoch ms
    criteria = {
        "Criterion": {
            "severity": {"GreaterThanOrEqual": 4, "LessThanOrEqual": 8},
            "updatedAt": {"GreaterThan": ts_gt, "LessThan": ts_lt},
        }
    }
    name = ctx.unique_name("sim2real-gd-filter-")
    gd.create_filter(
        DetectorId=detector_id,
        Name=name,
        FindingCriteria=criteria,
        Action="NOOP",
        Rank=1,
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: gd.delete_filter(DetectorId=detector_id, FilterName=name))

    got = gd.get_filter(DetectorId=detector_id, FilterName=name)
    crit = got["FindingCriteria"]["Criterion"]
    assert crit["severity"]["GreaterThanOrEqual"] == 4, crit["severity"]
    assert crit["severity"]["LessThanOrEqual"] == 8, crit["severity"]
    assert crit["updatedAt"]["GreaterThan"] == ts_gt, crit["updatedAt"]
    assert crit["updatedAt"]["LessThan"] == ts_lt, crit["updatedAt"]

    # UpdateFilter with a distinct nested range/timestamp combination must also round-trip
    # exactly -- proving the update path doesn't coerce/truncate either.
    new_ts_gt = ts_gt + 86_400_000
    new_ts_lt = ts_lt - 86_400_000
    new_criteria = {
        "Criterion": {
            "severity": {"GreaterThanOrEqual": 2, "LessThanOrEqual": 6},
            "updatedAt": {"GreaterThan": new_ts_gt, "LessThan": new_ts_lt},
        }
    }
    gd.update_filter(DetectorId=detector_id, FilterName=name, FindingCriteria=new_criteria)

    got2 = gd.get_filter(DetectorId=detector_id, FilterName=name)
    crit2 = got2["FindingCriteria"]["Criterion"]
    assert crit2["severity"]["GreaterThanOrEqual"] == 2, crit2["severity"]
    assert crit2["severity"]["LessThanOrEqual"] == 6, crit2["severity"]
    assert crit2["updatedAt"]["GreaterThan"] == new_ts_gt, crit2["updatedAt"]
    assert crit2["updatedAt"]["LessThan"] == new_ts_lt, crit2["updatedAt"]
    # the old range must be fully replaced, not merged
    assert crit2["severity"].get("GreaterThanOrEqual") != 4, crit2["severity"]


def _ensure_detector(ctx, gd) -> str:
    """Create a GuardDuty detector, or adopt the account's existing one.

    GuardDuty allows only one detector per account/region, so a concurrently
    running check (or a leftover from a previous run) may already own it. An
    adopted detector is never torn down by this check.
    """
    try:
        detector_id = gd.create_detector(Enable=True, Tags=_TAGS)["DetectorId"]
        ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))
        return detector_id
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "BadRequestException":
            raise
        existing = gd.list_detectors().get("DetectorIds", [])
        if not existing:
            raise
        return existing[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
