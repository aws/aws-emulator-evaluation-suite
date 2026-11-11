"""filter-rank-out-of-range-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "filter-rank-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["guardduty"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """CreateFilter with Rank outside the documented 1-100 range is rejected with
    BadRequestException, no filter is left behind under that name, and a
    positive control (same name, valid Rank) succeeds right after."""
    gd = ctx.client("guardduty")
    detector_id = _ensure_detector(ctx, gd)

    name = ctx.unique_name("sim2real-filter-rank-")
    criteria = {"Criterion": {"severity": {"GreaterThanOrEqual": 1}}}

    err = _error(
        lambda: gd.create_filter(
            DetectorId=detector_id,
            Name=name,
            Action="NOOP",
            Rank=150,  # out of the documented 1-100 range
            FindingCriteria=criteria,
        )
    )
    assert err["Code"] == "BadRequestException", err
    assert err["Message"] == (
        "The request is rejected because the one or more input parameters have invalid values."
    ), err

    # Effect absent: no filter was created under this name.
    absent = _error(lambda: gd.get_filter(DetectorId=detector_id, FilterName=name))
    assert absent["Code"] == "BadRequestException", absent
    assert absent["Message"] == "The request is rejected since no such resource found.", absent
    existing_names = gd.list_filters(DetectorId=detector_id).get("FilterNames", [])
    assert name not in existing_names, f"rejected filter {name!r} leaked into {existing_names}"

    # Positive control: the same name with a valid Rank succeeds. GuardDuty
    # requires a new filter's Rank to fit within the contiguous ordering of
    # the detector's existing filters (<= current-filter-count + 1), so on a
    # detector with zero pre-existing filters the only valid Rank is 1.
    gd.create_filter(
        DetectorId=detector_id,
        Name=name,
        Action="NOOP",
        Rank=1,
        FindingCriteria=criteria,
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: gd.delete_filter(DetectorId=detector_id, FilterName=name))
    got = gd.get_filter(DetectorId=detector_id, FilterName=name)
    assert got["Rank"] == 1, f"expected Rank 1 for the valid positive control, got {got['Rank']}"


def _ensure_detector(ctx, gd) -> str:
    try:
        detector_id = gd.create_detector(Enable=True, Tags={"sim2real-check": CHECK})["DetectorId"]
        ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))
        return detector_id
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "BadRequestException":
            raise
        existing = gd.list_detectors().get("DetectorIds", [])
        if not existing:
            raise
        return existing[0]


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
