"""findings-archive-unarchive-transition."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "findings-archive-unarchive-transition"
GROUP = "state-machine"
SERVICES = ["guardduty"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """Sample findings move from active to archived via ArchiveFindings and
    back to active via UnarchiveFindings, verified via GetFindings'
    Service.Archived field."""
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

    # A finding id can be visible in ListFindings slightly before GetFindings can
    # fetch it (indexing lag); poll for fetchability instead of assuming it.
    initial = _poll_until(
        lambda: gd.get_findings(DetectorId=detector_id, FindingIds=[finding_id]).get("Findings", []),
        lambda findings: len(findings) >= 1,
        timeout_s=60.0,
        interval_s=3.0,
    )[0]
    assert initial["Service"]["Archived"] is False, (
        f"expected freshly-created finding {finding_id} to be unarchived, "
        f"got Service.Archived={initial['Service']['Archived']!r}"
    )

    gd.archive_findings(DetectorId=detector_id, FindingIds=[finding_id])

    archived = _poll_until(
        lambda: gd.get_findings(DetectorId=detector_id, FindingIds=[finding_id])["Findings"][0],
        lambda f: f["Service"]["Archived"] is True,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert archived["Service"]["Archived"] is True, (
        f"expected finding {finding_id} to be archived after ArchiveFindings, "
        f"got Service.Archived={archived['Service']['Archived']!r}"
    )

    gd.unarchive_findings(DetectorId=detector_id, FindingIds=[finding_id])

    unarchived = _poll_until(
        lambda: gd.get_findings(DetectorId=detector_id, FindingIds=[finding_id])["Findings"][0],
        lambda f: f["Service"]["Archived"] is False,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert unarchived["Service"]["Archived"] is False, (
        f"expected finding {finding_id} to be unarchived after UnarchiveFindings, "
        f"got Service.Archived={unarchived['Service']['Archived']!r}"
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
    detector_id = gd.create_detector(
        Enable=True, Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
    )["DetectorId"]

    def _cleanup():
        try:
            gd.delete_detector(DetectorId=detector_id)
        except ClientError as err:
            # GuardDuty reports a detector that is already gone as BadRequestException.
            if err.response["Error"]["Code"] != "BadRequestException":
                raise

    ctx.on_cleanup(_cleanup)
    return detector_id


def _safe_unarchive(ctx, detector_id: str, finding_id: str) -> None:
    gd = ctx.client("guardduty")
    try:
        gd.unarchive_findings(DetectorId=detector_id, FindingIds=[finding_id])
    except ClientError as err:
        # GuardDuty reports a finding id the detector does not hold as BadRequestException.
        if err.response["Error"]["Code"] != "BadRequestException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
