"""finding-feedback-comments-unicode-preserved."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "finding-feedback-comments-unicode-preserved"
GROUP = "representation"
SERVICES = ["guardduty"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """UpdateFindingsFeedback with a non-ASCII comment is accepted and GetFindings then
    reports Service.UserFeedback USEFUL for the finding, which had no feedback before."""
    gd = ctx.client("guardduty")

    detector_id = _ensure_detector(ctx, gd)

    before_ids = set(gd.list_findings(DetectorId=detector_id).get("FindingIds", []))
    gd.create_sample_findings(DetectorId=detector_id)
    finding_id = _wait_for_a_new_finding(ctx, gd, detector_id, before_ids)

    baseline = _wait_for_finding_gettable(ctx, gd, detector_id, finding_id)
    baseline_feedback = baseline[0].get("Service", {}).get("UserFeedback")
    assert baseline_feedback is None, (
        f"finding {finding_id!r} already carried UserFeedback={baseline_feedback!r} "
        "before any UpdateFindingsFeedback call -- a stale finding, not a fresh one"
    )

    comment = "Расследовано — 誤検知ではない — confirmé faux positif"
    gd.update_findings_feedback(
        DetectorId=detector_id,
        FindingIds=[finding_id],
        Feedback="USEFUL",
        Comments=comment,
    )

    findings = _wait_for_feedback_to_land(ctx, gd, detector_id, finding_id)
    assert len(findings) == 1, f"expected exactly 1 finding for {finding_id!r}, got {len(findings)}"
    actual_feedback = findings[0]["Service"].get("UserFeedback")
    assert actual_feedback == "USEFUL", (
        f"finding {finding_id!r}: expected UserFeedback=USEFUL after UpdateFindingsFeedback "
        f"with a non-ASCII Comments string, got {actual_feedback!r}"
    )


def _ensure_detector(ctx, gd) -> str:
    """Create-or-adopt: GuardDuty allows exactly one detector per account per region,
    so CreateDetector on an account that already has one fails BadRequestException."""
    try:
        detector_id = gd.create_detector(Enable=True)["DetectorId"]
        ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))
        return detector_id
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "BadRequestException":
            raise
        existing = gd.list_detectors().get("DetectorIds", [])
        if not existing:
            raise
        return existing[0]


def _wait_for_a_new_finding(
    ctx, gd, detector_id: str, before_ids: set[str], timeout_s: float = 30.0
) -> str:
    """Diffs against the pre-CreateSampleFindings id set rather than taking
    ListFindings[0], because an adopted (pre-existing) detector may already carry
    findings from earlier runs -- including ones with feedback already set, which
    would poison the baseline-is-absent assertion below."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        after_ids = set(gd.list_findings(DetectorId=detector_id).get("FindingIds", []))
        new_ids = after_ids - before_ids
        if new_ids:
            return next(iter(new_ids))
        time.sleep(2)
    raise AssertionError("CreateSampleFindings produced no new listable findings in time")


def _wait_for_finding_gettable(ctx, gd, detector_id: str, finding_id: str, timeout_s: float = 30.0):
    """GetFindings lags ListFindings' index (a finding appears in the list before the
    finding store will return it by id), so a fresh finding_id can 404-empty on GetFindings
    for a few seconds even though ListFindings already returned it."""
    deadline = time.monotonic() + timeout_s
    last: list = []
    while time.monotonic() < deadline:
        last = gd.get_findings(DetectorId=detector_id, FindingIds=[finding_id]).get("Findings", [])
        if len(last) == 1:
            return last
        time.sleep(2)
    raise AssertionError(f"GetFindings never returned {finding_id!r} in time (last: {last})")


def _wait_for_feedback_to_land(ctx, gd, detector_id: str, finding_id: str, timeout_s: float = 150.0):
    """GetFindings can lag both ListFindings (eventual consistency between the
    finding index and the finding store) and UpdateFindingsFeedback (the feedback
    value itself is applied asynchronously and re-indexed), so poll generously until
    the finding is fetchable AND its Service.UserFeedback reflects the submitted
    feedback."""
    deadline = time.monotonic() + timeout_s
    last = []
    while time.monotonic() < deadline:
        last = gd.get_findings(DetectorId=detector_id, FindingIds=[finding_id]).get(
            "Findings", []
        )
        if len(last) == 1 and last[0].get("Service", {}).get("UserFeedback") == "USEFUL":
            return last
        time.sleep(5)
    raise AssertionError(f"GetFindings never reflected the submitted feedback (last: {last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
