"""create-filter-out-of-range-criteria-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-filter-out-of-range-criteria-rejected"
GROUP = "negative-classes"
SERVICES = ["guardduty"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """CreateFilter with a severity outside GuardDuty's documented 1-10 scale is rejected with
    BadRequestException and provisions no filter (the range rejection class), while an
    in-range severity filter on the same detector still succeeds (positive control)."""
    gd = ctx.client("guardduty")

    detector_id = gd.create_detector(Enable=True)["DetectorId"]
    ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))

    before = set(gd.list_filters(DetectorId=detector_id).get("FilterNames", []))

    bad_name = ctx.unique_name("sim2real-gd-filter-bad-")
    # registered before the call: if an over-permissive target accepts the
    # out-of-range severity, the filter it creates must still be reaped
    ctx.on_cleanup(lambda: _safe_delete_filter(gd, detector_id, bad_name))
    code, message = _error_code(
        lambda: gd.create_filter(
            DetectorId=detector_id,
            Name=bad_name,
            FindingCriteria={"Criterion": {"severity": {"Equals": ["15"]}}},
            Action="NOOP",
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    expected_message = (
        "The request was rejected because the parameter findingCriteria has invalid values in a condition."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no filter was provisioned by the rejected attempt
    after = set(gd.list_filters(DetectorId=detector_id).get("FilterNames", []))
    assert after == before, f"filter list changed after rejected CreateFilter: {before!r} -> {after!r}"
    assert bad_name not in after, f"rejected filter {bad_name!r} unexpectedly present in {after!r}"

    # positive control: an in-range severity value succeeds
    good_name = ctx.unique_name("sim2real-gd-filter-good-")
    gd.create_filter(
        DetectorId=detector_id,
        Name=good_name,
        FindingCriteria={"Criterion": {"severity": {"Equals": ["8"]}}},
        Action="NOOP",
    )
    ctx.on_cleanup(lambda: gd.delete_filter(DetectorId=detector_id, FilterName=good_name))
    listed = set(gd.list_filters(DetectorId=detector_id).get("FilterNames", []))
    assert good_name in listed, f"in-range severity filter {good_name!r} missing from {listed!r}"


# ===== helpers =====
def _safe_delete_filter(gd, detector_id, name):
    try:
        gd.delete_filter(DetectorId=detector_id, FilterName=name)
    except ClientError as exc:
        # GuardDuty reports a filter name that does not exist as BadRequestException.
        if exc.response["Error"]["Code"] != "BadRequestException":
            raise


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
