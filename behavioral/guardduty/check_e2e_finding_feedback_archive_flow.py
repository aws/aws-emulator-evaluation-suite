"""e2e-finding-feedback-archive-flow."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "e2e-finding-feedback-archive-flow"
GROUP = "e2e"
SERVICES = ["guardduty"]

_ACTIVE_CRITERIA = {"Criterion": {"service.archived": {"Eq": ["false"]}}}
_ARCHIVED_CRITERIA = {"Criterion": {"service.archived": {"Eq": ["true"]}}}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """Generate sample findings, submit feedback, archive them, and confirm the archived
    findings are excluded from the active (service.archived=false) ListFindings/GetFindings
    view, then unarchive and confirm reappearance.
    """
    gd = ctx.client("guardduty")
    detector_id, owned = _get_or_create_detector(ctx, gd)
    if owned:
        ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))

    gd.create_sample_findings(DetectorId=detector_id)
    finding_ids = _poll_for_findings(gd, detector_id, _ACTIVE_CRITERIA, min_count=1, timeout_s=60.0)
    target_ids = finding_ids[: min(3, len(finding_ids))]

    gd.update_findings_feedback(DetectorId=detector_id, FindingIds=target_ids, Feedback="USEFUL")

    def _feedback_recorded():
        findings = gd.get_findings(DetectorId=detector_id, FindingIds=target_ids)["Findings"]
        return all(f["Service"].get("UserFeedback") == "USEFUL" for f in findings)

    assert _poll_until(_feedback_recorded, timeout_s=90.0, interval_s=3.0), (
        "submitted USEFUL feedback never appeared as Service.UserFeedback via GetFindings"
    )

    gd.archive_findings(DetectorId=detector_id, FindingIds=target_ids)

    def _all_archived():
        findings = gd.get_findings(DetectorId=detector_id, FindingIds=target_ids)["Findings"]
        return all(f["Service"]["Archived"] for f in findings)

    assert _poll_until(_all_archived, timeout_s=90.0, interval_s=3.0), "findings never became archived"

    def _excluded_from_active():
        active_ids = set(_list_all_findings(gd, detector_id, _ACTIVE_CRITERIA))
        return not (set(target_ids) & active_ids)

    assert _poll_until(
        _excluded_from_active, timeout_s=120.0, interval_s=5.0
    ), "archived findings still visible in active view after archiving"

    def _included_in_archived():
        archived_ids = set(_list_all_findings(gd, detector_id, _ARCHIVED_CRITERIA))
        return set(target_ids) <= archived_ids

    assert _poll_until(
        _included_in_archived, timeout_s=120.0, interval_s=5.0
    ), "archived findings missing from archived view"

    gd.unarchive_findings(DetectorId=detector_id, FindingIds=target_ids)

    def _all_unarchived():
        findings = gd.get_findings(DetectorId=detector_id, FindingIds=target_ids)["Findings"]
        return all(not f["Service"]["Archived"] for f in findings)

    assert _poll_until(_all_unarchived, timeout_s=90.0, interval_s=3.0), "findings never became unarchived"

    def _reappeared_in_active():
        active_ids_after = set(_list_all_findings(gd, detector_id, _ACTIVE_CRITERIA))
        return set(target_ids) <= active_ids_after

    assert _poll_until(
        _reappeared_in_active, timeout_s=120.0, interval_s=5.0
    ), "unarchived findings did not reappear in active view"


def _get_or_create_detector(ctx, gd):
    from botocore.exceptions import ClientError

    existing = gd.list_detectors().get("DetectorIds", [])
    if existing:
        return existing[0], False
    try:
        detector_id = gd.create_detector(
            Enable=True,
            FindingPublishingFrequency="FIFTEEN_MINUTES",
            Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        )["DetectorId"]
        return detector_id, True
    except ClientError:
        existing = gd.list_detectors().get("DetectorIds", [])
        if existing:
            return existing[0], False
        raise


def _list_all_findings(gd, detector_id, criteria):
    ids: list[str] = []
    next_token = None
    while True:
        kwargs = {"DetectorId": detector_id, "FindingCriteria": criteria, "MaxResults": 50}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = gd.list_findings(**kwargs)
        ids.extend(resp.get("FindingIds", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return ids


def _poll_for_findings(gd, detector_id, criteria, min_count, timeout_s):
    deadline = time.monotonic() + timeout_s
    ids: list[str] = []
    while time.monotonic() < deadline:
        ids = _list_all_findings(gd, detector_id, criteria)
        if len(ids) >= min_count:
            return ids
        time.sleep(3)
    raise AssertionError(f"expected at least {min_count} findings, got {len(ids)} after {timeout_s}s")


def _poll_until(predicate, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval_s)
    return predicate()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
