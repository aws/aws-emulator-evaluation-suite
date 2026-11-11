"""filter-delete-already-deleted-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "filter-delete-already-deleted-rejected"
GROUP = "state-machine"
SERVICES = ["guardduty"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """DeleteFilter on an already-deleted filter name is rejected with BadRequestException (not
    accepted as idempotent) and the filter stays absent, while recreating the name restores the
    identical delete to success and a fresh filter still deletes normally (positive control)."""
    gd = ctx.client("guardduty")
    detector_id, _ = _get_or_create_detector(ctx)

    name = ctx.unique_name("sim2real-filt-dbldel-")[:64]
    criteria = {"Criterion": {"type": {"Equals": ["Recon:EC2/PortProbeUnprotectedPort"]}}}
    filter_tags = {"sim2real:managed": "true"}
    gd.create_filter(DetectorId=detector_id, Name=name, FindingCriteria=criteria, Tags=filter_tags)
    gd.delete_filter(DetectorId=detector_id, FilterName=name)

    err = _error(lambda: gd.delete_filter(DetectorId=detector_id, FilterName=name))
    assert err["Code"] == "BadRequestException", f"expected BadRequestException, got {err}"
    assert err["Message"] == "The request is rejected because the given filter name is invalid.", (
        f"unexpected message {err['Message']!r}"
    )

    names = gd.list_filters(DetectorId=detector_id).get("FilterNames", [])
    assert name not in names, "deleted filter must not reappear in ListFilters"

    # restore: recreating the same name makes the identical delete call valid again
    gd.create_filter(DetectorId=detector_id, Name=name, FindingCriteria=criteria, Tags=filter_tags)
    ctx.on_cleanup(lambda: _safe_delete_filter(gd, detector_id, name))
    gd.delete_filter(DetectorId=detector_id, FilterName=name)
    names_after_restore = gd.list_filters(DetectorId=detector_id).get("FilterNames", [])
    assert name not in names_after_restore, (
        "restored filter must be gone after the identical delete call succeeds"
    )

    # positive control: a distinct filter can still be created and deleted normally
    control_name = ctx.unique_name("sim2real-filt-control-")[:64]
    gd.create_filter(
        DetectorId=detector_id, Name=control_name, FindingCriteria=criteria, Tags=filter_tags
    )
    ctx.on_cleanup(lambda: _safe_delete_filter(gd, detector_id, control_name))
    got = gd.get_filter(DetectorId=detector_id, FilterName=control_name)
    assert got["Name"] == control_name, f"expected Name={control_name!r}, got {got.get('Name')!r}"
    gd.delete_filter(DetectorId=detector_id, FilterName=control_name)
    still_there = gd.list_filters(DetectorId=detector_id).get("FilterNames", [])
    assert control_name not in still_there, "control filter must be gone after delete"


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
