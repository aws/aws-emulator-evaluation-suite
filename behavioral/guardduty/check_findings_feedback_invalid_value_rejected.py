"""findings-feedback-invalid-value-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "findings-feedback-invalid-value-rejected"
GROUP = "overly-permissive"
SERVICES = ["guardduty"]

_FINDING_TYPE = "UnauthorizedAccess:EC2/SSHBruteForce"


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """UpdateFindingsFeedback with a Feedback value outside USEFUL/NOT_USEFUL
    fails with BadRequestException and its exact message and leaves UserFeedback
    unset; a valid USEFUL call on the same finding then succeeds."""
    gd = ctx.client("guardduty")
    detector_id = _ensure_detector(ctx)
    finding_id = _create_and_wait_for_new_finding(ctx, detector_id, _FINDING_TYPE)

    baseline = _wait_for_finding(gd, detector_id, finding_id)
    assert baseline["Service"].get("UserFeedback") is None, (
        "setup invariant violated: freshly-created sample finding already has UserFeedback set"
    )

    err = _error(
        lambda: gd.update_findings_feedback(
            DetectorId=detector_id, FindingIds=[finding_id], Feedback="MAYBE_USEFUL"
        )
    )
    assert err["Code"] == "BadRequestException", (
        f"expected BadRequestException for an out-of-enum Feedback value, got {err!r}"
    )
    expected = "The request is rejected because the JSON could not be processed."
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

    after_bad_call = _wait_for_finding(gd, detector_id, finding_id)
    assert after_bad_call["Service"].get("UserFeedback") is None, (
        "the rejected feedback update was persisted despite the BadRequestException"
    )

    # Positive control: a valid Feedback value on the same finding still succeeds.
    gd.update_findings_feedback(DetectorId=detector_id, FindingIds=[finding_id], Feedback="USEFUL")
    feedback = _poll_user_feedback(gd, detector_id, finding_id, expected="USEFUL")
    assert feedback == "USEFUL", f"positive control failed: UserFeedback was {feedback!r}"


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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


def _wait_for_finding(gd, detector_id: str, finding_id: str, *, timeout_s: float = 60.0) -> dict:
    """GetFindings can lag ListFindings' own visibility of the same id by a few seconds, so a read
    immediately after ListFindings first shows the id can come back with an empty Findings list.
    Bounded-retry the read instead of indexing it blindly."""
    deadline = time.monotonic() + timeout_s
    while True:
        resp = gd.get_findings(DetectorId=detector_id, FindingIds=[finding_id])
        findings = resp.get("Findings", [])
        if findings:
            return findings[0]
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"finding {finding_id!r} never became visible to GetFindings within {timeout_s}s"
            )
        time.sleep(2.0)


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
