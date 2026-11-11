"""e2e-sample-findings-archive-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-sample-findings-archive-lifecycle"
GROUP = "ordering"
SERVICES = ["guardduty"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """After archiving a subset of sample findings, ListFindings with
    service.archived=false returns only the others and service.archived=true exactly the
    subset, and GetFindings reports Service.Archived True for each archived finding."""
    gd = ctx.client("guardduty")
    detector_id = _ensure_detector(ctx, gd)

    # Request several distinct finding types explicitly so the check does not
    # depend on how many sample types the account/region happens to support.
    finding_types = [
        "Recon:EC2/PortProbeUnprotectedPort",
        "UnauthorizedAccess:EC2/SSHBruteForce",
        "Trojan:EC2/BlackholeTraffic",
        "Backdoor:EC2/C&CActivity.B",
    ]
    gd.create_sample_findings(DetectorId=detector_id, FindingTypes=finding_types)
    all_ids = _poll_finding_ids(ctx, gd, detector_id, min_count=2)
    assert len(all_ids) >= 2, "need at least 2 sample findings for this check"

    to_archive = all_ids[:2]
    keep_unarchived = all_ids[2:]

    # Newly created sample findings can lag briefly between being visible in
    # ListFindings and being fully indexed for mutating operations like
    # ArchiveFindings ("invalid finding identifiers" if archived too soon).
    # Confirm each is fetchable via GetFindings before mutating them, then
    # retry the archive call itself against that same lag.
    _poll_get_findings(ctx, gd, detector_id, to_archive)
    _retry_archive(ctx, gd, detector_id, to_archive)

    # Poll: an explicit service.archived=false filter must eventually stop
    # returning the archived ids (but keep returning the untouched ones).
    unarchived_only = _poll_until_absent(ctx, gd, detector_id, to_archive)
    for finding_id in to_archive:
        assert finding_id not in unarchived_only, (
            f"{finding_id} still in service.archived=false ListFindings after archiving"
        )
    for finding_id in keep_unarchived:
        assert finding_id in unarchived_only, (
            f"{finding_id} unexpectedly missing from service.archived=false ListFindings"
        )

    # An explicit service.archived=true filter returns exactly the archived subset.
    archived_only = gd.list_findings(
        DetectorId=detector_id,
        FindingCriteria={"Criterion": {"service.archived": {"Eq": ["true"]}}},
        MaxResults=50,
    ).get("FindingIds", [])
    for finding_id in to_archive:
        assert finding_id in archived_only, f"{finding_id} missing from service.archived=true ListFindings"
    for finding_id in keep_unarchived:
        assert finding_id not in archived_only, (
            f"{finding_id} unexpectedly present in service.archived=true ListFindings"
        )

    # GetFindings still returns the archived findings explicitly, with the flag set.
    archived_findings = gd.get_findings(DetectorId=detector_id, FindingIds=to_archive)["Findings"]
    assert len(archived_findings) == len(to_archive), (
        f"expected {len(to_archive)} findings from GetFindings, got {len(archived_findings)}"
    )
    for finding in archived_findings:
        assert finding["Service"]["Archived"] is True, finding["Id"]


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


def _poll_finding_ids(ctx, gd, detector_id: str, min_count: int, timeout_s: float = 30.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        ids = gd.list_findings(DetectorId=detector_id, MaxResults=50).get("FindingIds", [])
        if len(ids) >= min_count:
            return ids
        time.sleep(1.0)
    raise AssertionError("sample findings never appeared")


def _poll_until_absent(ctx, gd, detector_id: str, archived_ids, timeout_s: float = 60.0):
    deadline = time.monotonic() + timeout_s
    remaining = []
    criteria = {"Criterion": {"service.archived": {"Eq": ["false"]}}}
    while time.monotonic() < deadline:
        remaining = gd.list_findings(
            DetectorId=detector_id, FindingCriteria=criteria, MaxResults=50
        ).get("FindingIds", [])
        if not any(fid in remaining for fid in archived_ids):
            return remaining
        time.sleep(3.0)
    return remaining


def _poll_get_findings(ctx, gd, detector_id: str, finding_ids, timeout_s: float = 30.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        found = gd.get_findings(DetectorId=detector_id, FindingIds=finding_ids)["Findings"]
        if len(found) == len(finding_ids):
            return found
        time.sleep(1.0)
    raise AssertionError(f"finding ids never became fetchable via GetFindings: {finding_ids}")


def _retry_archive(ctx, gd, detector_id: str, finding_ids, timeout_s: float = 30.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            gd.archive_findings(DetectorId=detector_id, FindingIds=finding_ids)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "BadRequestException":
                raise
            last_exc = exc
            time.sleep(2.0)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
