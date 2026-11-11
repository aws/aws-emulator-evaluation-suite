"""threatintelset-lifecycle."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "threatintelset-lifecycle"
GROUP = "state-machine"
SERVICES = ["guardduty"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """A ThreatIntelSet reaches ACTIVE, is ACTIVE under its new name after UpdateThreatIntelSet and
    reaches Status DELETED after DeleteThreatIntelSet; updating the deleted set fails with HTTP 400,
    InternalServerErrorException and its exact message."""
    gd = ctx.client("guardduty")
    detector_id = _get_or_create_detector(ctx)
    listing = _make_list_bucket(ctx, detector_id, "198.51.100.10\n198.51.100.11\n")

    name = ctx.unique_name("sim2real-gd-tis-")
    created = gd.create_threat_intel_set(
        DetectorId=detector_id,
        Name=name,
        Format="TXT",
        Location=listing["location"],
        Activate=True,
        Tags={"sim2real": CHECK},
    )
    tis_id = created["ThreatIntelSetId"]
    ctx.on_cleanup(lambda: _safe_delete(ctx, detector_id, tis_id))

    active = _poll_until(
        ctx,
        lambda: gd.get_threat_intel_set(DetectorId=detector_id, ThreatIntelSetId=tis_id),
        lambda r: r["Status"] in ("ACTIVE", "ERROR"),
        timeout_s=300.0,
        interval_s=2.0,
    )
    assert active["Status"] == "ACTIVE", f"ThreatIntelSet did not activate: {active}"

    new_name = ctx.unique_name("sim2real-gd-tis-renamed-")
    gd.update_threat_intel_set(DetectorId=detector_id, ThreatIntelSetId=tis_id, Name=new_name)

    renamed = _poll_until(
        ctx,
        lambda: gd.get_threat_intel_set(DetectorId=detector_id, ThreatIntelSetId=tis_id),
        lambda r: r["Name"] == new_name and r["Status"] in ("ACTIVE", "ERROR"),
        timeout_s=180.0,
        interval_s=2.0,
    )
    assert renamed["Status"] == "ACTIVE", f"expected ACTIVE after rename, got {renamed}"
    assert renamed["Name"] == new_name, f"rename did not take: {renamed['Name']!r} != {new_name!r}"

    gd.delete_threat_intel_set(DetectorId=detector_id, ThreatIntelSetId=tis_id)

    deleted = _poll_until(
        ctx,
        lambda: gd.get_threat_intel_set(DetectorId=detector_id, ThreatIntelSetId=tis_id),
        lambda r: r["Status"] == "DELETED",
        timeout_s=120.0,
        interval_s=2.0,
    )
    assert deleted["Status"] == "DELETED", f"expected DELETED, got {deleted}"

    try:
        gd.update_threat_intel_set(
            DetectorId=detector_id, ThreatIntelSetId=tis_id, Name=ctx.unique_name("sim2real-gd-tis-dead-")
        )
        raise AssertionError("update on a DELETED ThreatIntelSet unexpectedly succeeded")
    except ClientError as e:
        # A client-side refusal: HTTP 400, even though GuardDuty names the error code
        # InternalServerErrorException.
        code = e.response["Error"]["Code"]
        status = e.response["ResponseMetadata"]["HTTPStatusCode"]
        message = e.response["Error"].get("Message")
        assert status == 400, f"expected HTTP 400 updating a DELETED ThreatIntelSet, got {status}"
        assert code == "InternalServerErrorException", f"expected InternalServerErrorException, got {code}"
        expected = "The request is rejected. This operation is already in progress."
        assert message == expected, f"expected message {expected!r}, got {message!r}"


# ===== helpers =====

def _poll_until(ctx, probe, predicate, *, timeout_s: float = 120.0, interval_s: float = 2.0) -> Any:
    """Poll ``probe`` until ``predicate`` holds, to ``timeout_s`` capped by the time the run has left."""
    left = ctx.time_left()
    if left is not None:
        timeout_s = min(timeout_s, max(1.0, left - 5.0))
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
    detector_id = gd.create_detector(Enable=True, Tags={"sim2real": CHECK})["DetectorId"]

    def _cleanup():
        try:
            gd.delete_detector(DetectorId=detector_id)
        except ClientError as err:
            # GuardDuty reports a detector that is already gone as BadRequestException.
            if err.response["Error"]["Code"] != "BadRequestException":
                raise

    ctx.on_cleanup(_cleanup)
    return detector_id


def _safe_delete(ctx, detector_id: str, tis_id: str) -> None:
    gd = ctx.client("guardduty")
    try:
        gd.delete_threat_intel_set(DetectorId=detector_id, ThreatIntelSetId=tis_id)
    except ClientError as err:
        # GuardDuty reports a ThreatIntelSet that is already gone as BadRequestException.
        if err.response["Error"]["Code"] != "BadRequestException":
            raise


def _make_list_bucket(ctx, detector_id: str, content: str, key: str = "list.txt") -> dict[str, str]:
    """A private bucket holding the list; its policy grants GuardDuty s3:GetObject on the
    object only for this account and detector."""
    s3 = ctx.client("s3")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    detector_arn = f"arn:aws:guardduty:{ctx.region}:{account_id}:detector/{detector_id}"
    region = ctx.region
    bucket = ctx.unique_name("sim2real-gd-list-").lower()
    # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key=key, Body=content.encode("utf-8"))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowGuardDutyGetObject",
                "Effect": "Allow",
                "Principal": {"Service": "guardduty.amazonaws.com"},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/{key}",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id, "aws:SourceArn": detector_arn}
                },
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    location = ctx.s3_object_url(f"https://s3.{ctx.region}.amazonaws.com/{bucket}/{key}", bucket, key)
    return {"bucket": bucket, "key": key, "location": location}


def _delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
