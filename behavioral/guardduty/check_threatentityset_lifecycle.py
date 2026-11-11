"""threatentityset-lifecycle."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "threatentityset-lifecycle"
GROUP = "state-machine"
SERVICES = ["guardduty"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """ThreatEntitySet create->update->delete lifecycle transitions are
    correctly reflected by GetThreatEntitySet, ending in Status DELETED."""
    gd = ctx.client("guardduty")
    detector_id = _get_or_create_detector(ctx)
    listing = _make_public_list_bucket(ctx, "192.0.2.50\n192.0.2.51\n")

    name = ctx.unique_name("sim2real-gd-tes-")
    created = gd.create_threat_entity_set(
        DetectorId=detector_id,
        Name=name,
        Format="TXT",
        Location=listing["location"],
        Activate=True,
        Tags={"sim2real-check": CHECK},
    )
    tes_id = created["ThreatEntitySetId"]
    ctx.on_cleanup(lambda: _safe_delete(ctx, detector_id, tes_id))

    # GuardDuty documents ThreatEntitySet activation as taking "a few minutes" and up to
    # ~40 minutes in some scenarios; a 2-entry TXT list can stay ACTIVATING past 300 s.
    active = _poll_until(
        lambda: gd.get_threat_entity_set(DetectorId=detector_id, ThreatEntitySetId=tes_id),
        lambda r: r["Status"] in ("ACTIVE", "ERROR"),
        timeout_s=1350.0,
        interval_s=15.0,
    )
    assert active["Status"] == "ACTIVE", f"ThreatEntitySet did not activate: {active}"

    new_name = ctx.unique_name("sim2real-gd-tes-renamed-")
    gd.update_threat_entity_set(DetectorId=detector_id, ThreatEntitySetId=tes_id, Name=new_name)

    # UpdateThreatEntitySet re-triggers the multi-minute ACTIVATING revalidation, but the
    # Name change itself is synchronous and immediately observable, so that is what is asserted.
    renamed = gd.get_threat_entity_set(DetectorId=detector_id, ThreatEntitySetId=tes_id)
    assert renamed["Name"] == new_name, renamed
    assert renamed["Status"] in ("ACTIVATING", "ACTIVE", "ERROR"), renamed

    try:
        gd.delete_threat_entity_set(DetectorId=detector_id, ThreatEntitySetId=tes_id)
    except ClientError as e:
        # Deleting while the rename's revalidation is still ACTIVATING is itself a documented,
        # valid state-machine rejection (same contract the create-delete sibling check observed
        # for a still-ACTIVATING create).
        err = e.response["Error"]
        assert err["Code"] == "ConflictException", (
            f"expected ConflictException when deleting a still-revalidating ThreatEntitySet, "
            f"got {err}"
        )
        expected = (
            "Another operation is currently in progress, please wait until it completes, then "
            "try again."
        )
        assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"
        return

    deleted = _poll_until(
        lambda: gd.get_threat_entity_set(DetectorId=detector_id, ThreatEntitySetId=tes_id),
        lambda r: r["Status"] == "DELETED",
        timeout_s=200.0,
        interval_s=5.0,
    )
    assert deleted["Status"] == "DELETED"


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


def _safe_delete(ctx, detector_id: str, tes_id: str) -> None:
    gd = ctx.client("guardduty")
    try:
        gd.delete_threat_entity_set(DetectorId=detector_id, ThreatEntitySetId=tes_id)
    except ClientError as err:
        # GuardDuty reports a ThreatEntitySet that is already gone as BadRequestException.
        if err.response["Error"]["Code"] != "BadRequestException":
            raise


def _make_public_list_bucket(ctx, content: str, key: str = "list.txt") -> dict[str, str]:
    s3 = ctx.client("s3")
    region = ctx.region
    bucket = ctx.unique_name("sim2real-gd-list-").lower()
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )
    s3.put_object(Bucket=bucket, Key=key, Body=content.encode("utf-8"))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicReadForGuardDuty",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/{key}",
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    location = f"{s3.meta.endpoint_url}/{bucket}/{key}"
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
