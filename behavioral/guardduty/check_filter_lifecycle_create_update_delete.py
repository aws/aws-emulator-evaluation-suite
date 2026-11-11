"""filter-lifecycle-create-update-delete."""
from __future__ import annotations


from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "filter-lifecycle-create-update-delete"
GROUP = "state-machine"
SERVICES = ["guardduty"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """CreateFilter persists criteria, UpdateFilter mutates in place, DeleteFilter removes it."""
    gd = ctx.client("guardduty")
    detector_id, _ = _get_or_create_detector(ctx)

    name = ctx.unique_name("sim2real-filt-")[:64]
    initial_criteria = {"Criterion": {"type": {"Equals": ["Recon:EC2/PortProbeUnprotectedPort"]}}}
    # Rank must be within [1, 100] on real AWS (GuardDuty rejects out-of-bound ranks with
    # BadRequestException); use the low end of the range to stay valid regardless of how
    # many other filters already exist on this detector.
    gd.create_filter(
        DetectorId=detector_id,
        Name=name,
        Description="initial description",
        Rank=1,
        FindingCriteria=initial_criteria,
    )
    ctx.on_cleanup(lambda: _safe_delete_filter(gd, detector_id, name))

    got = gd.get_filter(DetectorId=detector_id, FilterName=name)
    assert got["Name"] == name
    assert got["Description"] == "initial description"
    assert got["Rank"] == 1
    assert got["FindingCriteria"]["Criterion"]["type"]["Equals"] == [
        "Recon:EC2/PortProbeUnprotectedPort"
    ]

    updated_criteria = {"Criterion": {"type": {"Equals": ["Backdoor:EC2/C&CActivity.B!DNS"]}}}
    # Rank is omitted here: GuardDuty treats Rank as a *position among existing filters*, not
    # an absolute free-form integer -- on UpdateFilter its valid range is [1, existingFilterCount],
    # so with only this one filter on the detector the only valid rank is 1 (its own position).
    # Exercise the "mutates in place" contract via Description/FindingCriteria instead.
    gd.update_filter(
        DetectorId=detector_id,
        FilterName=name,
        Description="updated description",
        FindingCriteria=updated_criteria,
    )

    got2 = gd.get_filter(DetectorId=detector_id, FilterName=name)
    assert got2["Description"] == "updated description"
    assert got2["Rank"] == 1
    assert got2["FindingCriteria"]["Criterion"]["type"]["Equals"] == [
        "Backdoor:EC2/C&CActivity.B!DNS"
    ]

    gd.delete_filter(DetectorId=detector_id, FilterName=name)

    err = _error(lambda: gd.get_filter(DetectorId=detector_id, FilterName=name))
    assert err["Code"] == "BadRequestException", f"expected BadRequestException, got {err}"
    assert err["Message"] == "The request is rejected since no such resource found.", f"unexpected message {err['Message']!r}"


# ===== helpers =====


def _get_or_create_detector(ctx):
    gd = ctx.client("guardduty")
    existing = gd.list_detectors().get("DetectorIds", [])
    if existing:
        return existing[0], False
    resp = gd.create_detector(Enable=True)
    detector_id = resp["DetectorId"]
    ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))
    return detector_id, True


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a
    target accepting a call real AWS refuses must not be reduced to a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete_filter(gd, detector_id, name):
    try:
        gd.delete_filter(DetectorId=detector_id, FilterName=name)
    except ClientError as exc:
        # GuardDuty reports a filter name that is already gone as BadRequestException.
        if exc.response["Error"]["Code"] != "BadRequestException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
