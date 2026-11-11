"""e2e-threat-intel-match-detection-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-threat-intel-match-detection-flow"
GROUP = "e2e"
SERVICES = ["guardduty"]

_SAMPLE_TYPE = "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom"


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """A ThreatIntelSet whose S3 list GuardDuty fetches reaches ACTIVE, a sample finding
    created afterward is returned by GetFindings, and deleting the set (Status DELETED)
    leaves that finding readable."""
    gd = ctx.client("guardduty")
    detector_id, owned = _get_or_create_detector(ctx, gd)
    if owned:
        ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))

    bucket, key, location = _put_threat_list(ctx)
    set_name = ctx.unique_name("sim2real-behav-threatintel-")
    threat_intel_set_id = gd.create_threat_intel_set(
        DetectorId=detector_id,
        Name=set_name,
        Format="TXT",
        Location=location,
        Activate=True,
    )["ThreatIntelSetId"]
    ctx.on_cleanup(lambda: _safe_delete_threat_intel_set(gd, detector_id, threat_intel_set_id))

    status = _poll_threat_intel_set_status(gd, detector_id, threat_intel_set_id, timeout_s=120.0)
    assert status == "ACTIVE", f"expected ACTIVE, got {status}"

    gd.create_sample_findings(DetectorId=detector_id, FindingTypes=[_SAMPLE_TYPE])

    finding_id = _poll_for_finding_of_type(gd, detector_id, _SAMPLE_TYPE, timeout_s=60.0)
    finding = _poll_for_getfindings(gd, detector_id, finding_id, timeout_s=60.0)
    assert finding["Type"] == _SAMPLE_TYPE, f"expected type {_SAMPLE_TYPE}, got {finding['Type']}"
    assert finding["Id"] == finding_id, f"expected id {finding_id}, got {finding['Id']}"

    gd.delete_threat_intel_set(DetectorId=detector_id, ThreatIntelSetId=threat_intel_set_id)

    # deletion is asynchronous (ThreatIntelSetStatus: ACTIVE->DEACTIVATING->DELETE_PENDING->
    # DELETED); poll past the transient states to the terminal DELETED status.
    deleted_status = _poll_threat_intel_set_deleted(gd, detector_id, threat_intel_set_id, timeout_s=300.0)
    assert deleted_status == "DELETED", f"expected the terminal DELETED status, got {deleted_status}"

    # the previously created finding must remain fully intact and retrievable
    finding_after = _poll_for_getfindings(gd, detector_id, finding_id, timeout_s=60.0)
    assert finding_after["Id"] == finding_id, f"expected id {finding_id}, got {finding_after['Id']}"
    assert finding_after["Type"] == _SAMPLE_TYPE, (
        f"expected type {_SAMPLE_TYPE}, got {finding_after['Type']}"
    )


# ===== helpers =====
def _get_or_create_detector(ctx, gd):
    from botocore.exceptions import ClientError

    existing = gd.list_detectors().get("DetectorIds", [])
    if existing:
        return existing[0], False
    try:
        detector_id = gd.create_detector(Enable=True, FindingPublishingFrequency="FIFTEEN_MINUTES")[
            "DetectorId"
        ]
        return detector_id, True
    except ClientError:
        existing = gd.list_detectors().get("DetectorIds", [])
        if existing:
            return existing[0], False
        raise


def _put_threat_list(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-gd-threatintel-").lower().replace("_", "-")
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    key = "threatintel.txt"
    body = b"198.51.100.42/32\n"
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowGuardDutyRead",
                "Effect": "Allow",
                "Principal": {"Service": "guardduty.amazonaws.com"},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/{key}",
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    location = f"https://{bucket}.s3.{ctx.region}.amazonaws.com/{key}"
    return bucket, key, location


def _poll_threat_intel_set_status(gd, detector_id, set_id, timeout_s):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = gd.get_threat_intel_set(DetectorId=detector_id, ThreatIntelSetId=set_id)["Status"]
        if status != "ACTIVATING":
            return status
        time.sleep(3)
    raise AssertionError(f"ThreatIntelSet {set_id} stayed ACTIVATING past {timeout_s}s")


def _poll_threat_intel_set_deleted(gd, detector_id, set_id, timeout_s):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = gd.get_threat_intel_set(DetectorId=detector_id, ThreatIntelSetId=set_id)["Status"]
        if status == "DELETED":
            return status
        time.sleep(5)
    raise AssertionError(f"ThreatIntelSet {set_id} did not reach DELETED within {timeout_s}s (last={status})")


def _safe_delete_threat_intel_set(gd, detector_id, set_id):
    from botocore.exceptions import ClientError

    try:
        if gd.get_threat_intel_set(DetectorId=detector_id, ThreatIntelSetId=set_id)["Status"] != "DELETED":
            gd.delete_threat_intel_set(DetectorId=detector_id, ThreatIntelSetId=set_id)
    except ClientError as exc:
        # GuardDuty reports a ThreatIntelSet that is already gone as BadRequestException.
        if exc.response["Error"]["Code"] != "BadRequestException":
            raise


def _poll_for_finding_of_type(gd, detector_id, finding_type, timeout_s):
    criteria = {"Criterion": {"type": {"Eq": [finding_type]}}}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        ids = gd.list_findings(DetectorId=detector_id, FindingCriteria=criteria).get("FindingIds", [])
        if ids:
            return ids[0]
        time.sleep(3)
    raise AssertionError(f"no finding of type {finding_type} appeared within {timeout_s}s")


def _poll_for_getfindings(gd, detector_id, finding_id, timeout_s):
    # ListFindings' search index can surface a finding ID slightly before GetFindings'
    # item store has it available; poll GetFindings until it resolves.
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        findings = gd.get_findings(DetectorId=detector_id, FindingIds=[finding_id]).get("Findings", [])
        if findings:
            return findings[0]
        time.sleep(3)
    raise AssertionError(f"GetFindings never returned finding {finding_id} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
