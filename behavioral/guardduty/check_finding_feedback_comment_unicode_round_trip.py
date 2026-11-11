"""finding-feedback-comment-unicode-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "finding-feedback-comment-unicode-round-trip"
GROUP = "state-machine"
SERVICES = ["guardduty"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """UpdateFindingsFeedback with a unicode comment, then an empty one, is
    accepted, and GetFindings reports each Feedback value sent (USEFUL, then
    NOT_USEFUL) in Service.UserFeedback."""
    gd = ctx.client("guardduty")
    detector_id = _ensure_detector(ctx, gd)

    gd.create_sample_findings(DetectorId=detector_id)
    finding_id = _poll_first_finding_id(ctx, gd, detector_id)

    baseline = _poll_get_finding(ctx, gd, detector_id, finding_id)
    baseline_feedback = baseline.get("Service", {}).get("UserFeedback")
    assert baseline_feedback is None, (
        f"expected no UserFeedback before any UpdateFindingsFeedback call, got {baseline_feedback!r}"
    )

    unicode_comment = "Iñtërnâtiônàlizætiøn 测试 — sample analyst comment \u2603"
    gd.update_findings_feedback(
        DetectorId=detector_id,
        FindingIds=[finding_id],
        Feedback="USEFUL",
        Comments=unicode_comment,
    )
    after_useful = _poll_user_feedback(ctx, gd, detector_id, finding_id, "USEFUL")
    assert after_useful == "USEFUL", (
        f"expected UserFeedback USEFUL after unicode-comment feedback, got {after_useful!r}"
    )

    # Empty (not absent) Comments must also be accepted and still update Feedback.
    gd.update_findings_feedback(
        DetectorId=detector_id,
        FindingIds=[finding_id],
        Feedback="NOT_USEFUL",
        Comments="",
    )
    after_not_useful = _poll_user_feedback(ctx, gd, detector_id, finding_id, "NOT_USEFUL")
    assert after_not_useful == "NOT_USEFUL", (
        f"expected UserFeedback NOT_USEFUL after empty-comment feedback, got {after_not_useful!r}"
    )


def _ensure_detector(ctx, gd) -> str:
    tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
    try:
        detector_id = gd.create_detector(Enable=True, Tags=tags)["DetectorId"]
        ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))
        return detector_id
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "BadRequestException":
            raise
        existing = gd.list_detectors().get("DetectorIds", [])
        if not existing:
            raise
        return existing[0]


def _poll_first_finding_id(ctx, gd, detector_id: str, timeout_s: float = 60.0) -> str:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        ids = gd.list_findings(DetectorId=detector_id, MaxResults=1).get("FindingIds", [])
        if ids:
            return ids[0]
        time.sleep(1.0)
    raise AssertionError("no findings appeared after CreateSampleFindings")


def _poll_get_finding(ctx, gd, detector_id: str, finding_id: str, timeout_s: float = 90.0) -> dict:
    """A freshly-listed finding id is not stably gettable right away: GetFindings can
    return it once and then an empty result on the very next call before it settles,
    so every read retries instead of trusting a single prior success."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        findings = gd.get_findings(DetectorId=detector_id, FindingIds=[finding_id]).get("Findings", [])
        if findings:
            return findings[0]
        time.sleep(2.0)
    raise AssertionError(f"GetFindings never returned {finding_id!r} within {timeout_s}s")


def _poll_user_feedback(ctx, gd, detector_id: str, finding_id: str, expected: str, timeout_s: float = 150.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        findings = gd.get_findings(DetectorId=detector_id, FindingIds=[finding_id]).get("Findings", [])
        if findings:
            last = findings[0].get("Service", {}).get("UserFeedback")
            if last == expected:
                return last
        time.sleep(1.0)
    raise AssertionError(
        f"UserFeedback never became {expected!r} within {timeout_s}s (last observed: {last!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
