"""create-filter-invalid-criteria-field-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-filter-invalid-criteria-field-rejected"
GROUP = "overly-permissive"
SERVICES = ["guardduty"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """CreateFilter with a FindingCriteria field name GuardDuty does not recognize is rejected
    with BadRequestException and leaves no filter behind, while a filter on a valid field in
    the same detector still succeeds (positive control)."""
    gd = ctx.client("guardduty")
    detector_id = _get_or_create_detector(ctx)
    bad_name = ctx.unique_name("sim2real-gd-filter-bad-")

    code, message = _error_code(
        lambda: gd.create_filter(
            DetectorId=detector_id,
            Name=bad_name,
            FindingCriteria={"Criterion": {"this.field.does.not.exist": {"Eq": ["x"]}}},
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    expected_message = "The request was rejected because the parameter findingCriteria has an invalid value."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    names_after_reject = gd.list_filters(DetectorId=detector_id).get("FilterNames", [])
    assert bad_name not in names_after_reject, (
        f"rejected filter {bad_name!r} must not appear in ListFilters, saw {names_after_reject!r}"
    )

    good_name = ctx.unique_name("sim2real-gd-filter-good-")
    gd.create_filter(
        DetectorId=detector_id,
        Name=good_name,
        FindingCriteria={"Criterion": {"severity": {"Gte": 1}}},
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-gd-filter-good-"},
    )
    ctx.on_cleanup(lambda: _safe_delete_filter(ctx, detector_id, good_name))

    good = gd.get_filter(DetectorId=detector_id, FilterName=good_name)
    got_gte = good["FindingCriteria"]["Criterion"]["severity"]["Gte"]
    assert got_gte == 1, f"expected positive-control filter severity.Gte == 1, got {got_gte!r}"


# ===== helpers =====

def _get_or_create_detector(ctx) -> str:
    gd = ctx.client("guardduty")
    ids = gd.list_detectors().get("DetectorIds", [])
    if ids:
        return ids[0]
    detector_id = gd.create_detector(Enable=True)["DetectorId"]

    def _cleanup():
        try:
            gd.delete_detector(DetectorId=detector_id)
        except ClientError as err:
            # GuardDuty reports a detector that is already gone as BadRequestException.
            if err.response["Error"]["Code"] != "BadRequestException":
                raise

    ctx.on_cleanup(_cleanup)
    return detector_id


def _safe_delete_filter(ctx, detector_id: str, name: str) -> None:
    gd = ctx.client("guardduty")
    try:
        gd.delete_filter(DetectorId=detector_id, FilterName=name)
    except ClientError as err:
        # GuardDuty reports a filter name that is already gone as BadRequestException.
        if err.response["Error"]["Code"] != "BadRequestException":
            raise


def _error_code(fn) -> Any:
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because an
    emulator ACCEPTING a criteria field real AWS refuses is the strongest signal available and
    must not be reduced to an error-code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects CreateFilter with an unrecognized criteria field, but it "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
