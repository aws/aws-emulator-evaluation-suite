"""archive-unarchive-findings-last-write-wins."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "archive-unarchive-findings-last-write-wins"
GROUP = "ordering"
SERVICES = ["guardduty"]

_FINDING_TYPE = "Trojan:EC2/BlackholeTraffic!DNS"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """Calling ArchiveFindings followed by UnarchiveFindings on the same finding
    ID leaves the finding unarchived (the later call wins), observed via
    Finding.Service.Archived through GetFindings.
    """
    gd = ctx.client("guardduty")
    detector_id = _ensure_detector(ctx)
    finding_id = _create_and_wait_for_new_finding(ctx, detector_id, _FINDING_TYPE)

    gd.archive_findings(DetectorId=detector_id, FindingIds=[finding_id])
    archived_first = _poll_archived(gd, detector_id, finding_id, expected=True)
    assert archived_first is True, (
        f"finding {finding_id} never reached Service.Archived=True after "
        "ArchiveFindings (positive control failed)"
    )

    gd.unarchive_findings(DetectorId=detector_id, FindingIds=[finding_id])
    archived = _poll_archived(gd, detector_id, finding_id, expected=False)

    assert archived is False, (
        f"finding {finding_id} was still archived after UnarchiveFindings ran "
        "after ArchiveFindings (last-write-wins violated)"
    )


def _ensure_detector(ctx) -> str:
    from botocore.exceptions import ClientError

    gd = ctx.client("guardduty")
    try:
        detector_id = gd.create_detector(Enable=True)["DetectorId"]
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


def _poll_archived(gd, detector_id: str, finding_id: str, *, expected: bool, timeout_s: float = 90.0):
    deadline = time.monotonic() + timeout_s
    archived = None
    while time.monotonic() < deadline:
        resp = gd.get_findings(DetectorId=detector_id, FindingIds=[finding_id])
        archived = resp["Findings"][0]["Service"]["Archived"]
        if archived == expected:
            return archived
        time.sleep(3.0)
    raise AssertionError(
        f"finding {finding_id} did not reach Service.Archived={expected} within "
        f"{timeout_s}s; last observed {archived!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
