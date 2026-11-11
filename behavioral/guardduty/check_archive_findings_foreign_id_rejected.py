"""archive-findings-foreign-id-rejected."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "archive-findings-foreign-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["guardduty"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """ArchiveFindings with a well-formed FindingId foreign to the detector is rejected with
    BadRequestException and leaves the real finding un-archived, while archiving the real
    finding by its correct id still succeeds (positive control)."""
    gd = ctx.client("guardduty")
    detector_id = _get_or_create_detector(ctx)

    gd.create_sample_findings(DetectorId=detector_id)
    finding_id = _poll_until(
        lambda: gd.list_findings(DetectorId=detector_id, MaxResults=1).get("FindingIds", []),
        lambda ids: len(ids) >= 1,
        timeout_s=60.0,
        interval_s=3.0,
    )[0]
    ctx.on_cleanup(lambda: _safe_unarchive(ctx, detector_id, finding_id))

    initial = _read_finding(gd, detector_id, finding_id)
    assert initial["Service"]["Archived"] is False, (
        f"finding {finding_id} was already archived before the check began: {initial['Service']}"
    )

    foreign_id = "f" * 32
    code, message = _error_code(
        lambda: gd.archive_findings(DetectorId=detector_id, FindingIds=[foreign_id])
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException archiving foreign FindingId {foreign_id!r} "
        f"against detector {detector_id}, got {code!r}"
    )
    expected_message = "The request is rejected because an invalid finding identifiers is specified."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    unaffected = _read_finding(gd, detector_id, finding_id)
    assert unaffected["Service"]["Archived"] is False, (
        f"finding {finding_id} was archived as a side effect of the rejected foreign-id "
        f"ArchiveFindings call: {unaffected['Service']}"
    )

    # a just-generated sample finding can briefly read back before ArchiveFindings accepts its id
    _poll_until(
        lambda: _archive_accepted(gd, detector_id, finding_id),
        lambda accepted: accepted,
        timeout_s=60.0,
        interval_s=3.0,
    )

    archived = _poll_until(
        lambda: _read_finding(gd, detector_id, finding_id),
        lambda f: f["Service"]["Archived"] is True,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert archived["Service"]["Archived"] is True, (
        f"finding {finding_id} did not report Archived=True via GetFindings after "
        f"ArchiveFindings on its real id: {archived['Service']}"
    )

    _poll_until(
        lambda: gd.list_findings(
            DetectorId=detector_id,
            FindingCriteria={
                "Criterion": {
                    "id": {"Eq": [finding_id]},
                    "service.archived": {"Eq": ["true"]},
                }
            },
        ).get("FindingIds", []),
        lambda ids: finding_id in ids,
        timeout_s=60.0,
        interval_s=3.0,
    )


# ===== helpers =====

def _poll_until(probe, predicate, *, timeout_s: float = 120.0, interval_s: float = 3.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last!r}")


def _get_or_create_detector(ctx) -> str:
    gd = ctx.client("guardduty")
    ids = gd.list_detectors().get("DetectorIds", [])
    if ids:
        return ids[0]
    detector_id = gd.create_detector(Enable=True, Tags={"sim2real-check": CHECK})["DetectorId"]

    def _cleanup():
        try:
            gd.delete_detector(DetectorId=detector_id)
        except ClientError as err:
            # GuardDuty reports a detector that is already gone as BadRequestException.
            if err.response["Error"]["Code"] != "BadRequestException":
                raise

    ctx.on_cleanup(_cleanup)
    return detector_id


def _read_finding(gd, detector_id: str, finding_id: str) -> dict:
    """GetFindings for one id, polled because a listed sample finding can briefly read back empty."""
    return _poll_until(
        lambda: gd.get_findings(DetectorId=detector_id, FindingIds=[finding_id])["Findings"],
        lambda found: len(found) == 1,
        timeout_s=60.0,
        interval_s=3.0,
    )[0]


def _archive_accepted(gd, detector_id: str, finding_id: str) -> bool:
    try:
        gd.archive_findings(DetectorId=detector_id, FindingIds=[finding_id])
    except ClientError as err:
        if err.response["Error"]["Code"] == "BadRequestException":
            return False
        raise
    return True


def _safe_unarchive(ctx, detector_id: str, finding_id: str) -> None:
    gd = ctx.client("guardduty")
    try:
        gd.unarchive_findings(DetectorId=detector_id, FindingIds=[finding_id])
    except ClientError as err:
        # GuardDuty reports a finding id the detector does not hold as BadRequestException.
        if err.response["Error"]["Code"] != "BadRequestException":
            raise


def _error_code(fn) -> Any:
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because a target
    that accepts a call real AWS rejects is the strongest signal available and must not be
    reduced to a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects ArchiveFindings on a foreign FindingId, but it SUCCEEDED and "
        f"returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
