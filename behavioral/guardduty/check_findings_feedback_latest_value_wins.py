"""findings-feedback-latest-value-wins."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "findings-feedback-latest-value-wins"
GROUP = "ordering"
SERVICES = ["guardduty"]

_FINDING_TYPE = "Recon:EC2/PortProbeUnprotectedPort"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """Multiple sequential UpdateFindingsFeedback calls on the same finding leave
    only the most recently submitted Feedback value persisted, observed via
    Finding.Service.UserFeedback through GetFindings.
    """
    gd = ctx.client("guardduty")
    detector_id = _ensure_detector(ctx)
    finding_id = _create_and_wait_for_new_finding(ctx, detector_id, _FINDING_TYPE)

    gd.update_findings_feedback(
        DetectorId=detector_id, FindingIds=[finding_id], Feedback="USEFUL", Comments="first"
    )
    first_feedback = _poll_user_feedback(gd, detector_id, finding_id, expected="USEFUL")
    assert first_feedback == "USEFUL", (
        f"finding {finding_id} UserFeedback was {first_feedback!r} after the first "
        "UpdateFindingsFeedback call, expected USEFUL to have taken effect before it "
        "is overwritten"
    )

    gd.update_findings_feedback(
        DetectorId=detector_id, FindingIds=[finding_id], Feedback="NOT_USEFUL", Comments="second"
    )
    feedback = _poll_user_feedback(gd, detector_id, finding_id, expected="NOT_USEFUL")

    assert feedback == "NOT_USEFUL", (
        f"finding {finding_id} UserFeedback was {feedback!r}, expected the most "
        "recently submitted value NOT_USEFUL to win"
    )


def _ensure_detector(ctx) -> str:
    from botocore.exceptions import ClientError

    gd = ctx.client("guardduty")
    try:
        detector_id = gd.create_detector(
            Enable=True, Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
        )["DetectorId"]
        created = True
    except ClientError as e:
        if e.response["Error"]["Code"] != "BadRequestException":
            raise
        ids = gd.list_detectors().get("DetectorIds", [])
        if not ids:
            raise
        detector_id = ids[0]
        created = False
    if created:
        ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))
    return detector_id


def _list_all_finding_ids(gd, detector_id: str, criteria: dict) -> set[str]:
    ids: set[str] = set()
    token = None
    while True:
        kwargs = {"DetectorId": detector_id, "FindingCriteria": criteria, "MaxResults": 50}
        if token:
            kwargs["NextToken"] = token
        resp = gd.list_findings(**kwargs)
        ids.update(resp.get("FindingIds", []))
        token = resp.get("NextToken")
        if not token:
            break
    return ids


def _create_and_wait_for_new_finding(ctx, detector_id: str, finding_type: str) -> str:
    gd = ctx.client("guardduty")
    criteria = {"Criterion": {"type": {"Equals": [finding_type]}}}
    before = _list_all_finding_ids(gd, detector_id, criteria)

    gd.create_sample_findings(DetectorId=detector_id, FindingTypes=[finding_type])

    deadline = time.monotonic() + 120.0
    new_ids: set[str] = set()
    while time.monotonic() < deadline:
        after = _list_all_finding_ids(gd, detector_id, criteria)
        new_ids = after - before
        if new_ids:
            break
        time.sleep(3.0)

    assert new_ids, f"no new finding of type {finding_type!r} appeared in ListFindings"
    return next(iter(new_ids))


def _poll_user_feedback(gd, detector_id: str, finding_id: str, *, expected: str, timeout_s: float = 90.0):
    deadline = time.monotonic() + timeout_s
    feedback = None
    while time.monotonic() < deadline:
        resp = gd.get_findings(DetectorId=detector_id, FindingIds=[finding_id])
        findings = resp.get("Findings", [])
        if findings:
            feedback = findings[0]["Service"].get("UserFeedback")
            if feedback == expected:
                return feedback
        time.sleep(3.0)
    return feedback


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
