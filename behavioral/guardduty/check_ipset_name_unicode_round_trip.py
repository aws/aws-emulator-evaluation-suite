"""ipset-name-unicode-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ipset-name-unicode-round-trip"
GROUP = "state-machine"
SERVICES = ["guardduty"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """GetIPSet returns an IPSet's name, location and non-ASCII tag value
    unchanged and ListIPSets lists its id; the tag carries the non-ASCII text
    because IPSet names allow only alphanumerics, spaces, - and _."""
    gd = ctx.client("guardduty")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    detector_id = _ensure_detector(ctx, gd)
    account_id = sts.get_caller_identity()["Account"]
    detector_arn = f"arn:aws:guardduty:{ctx.region}:{account_id}:detector/{detector_id}"

    bucket = ctx.unique_name("sim2real-gd-ip-").lower()
    _create_bucket(ctx, s3, bucket)

    key = "ip-lists/list.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"192.0.2.44\n192.0.2.45\n")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    _allow_guardduty_read(s3, bucket, key, account_id, detector_arn)

    location = f"s3://{bucket}/{key}"
    name = ctx.unique_name("sim2real-ip-") + "_trusted_set"
    unicode_tag_value = "ÜnïcödéトラストÑoño"

    resp = _retry_create_ip_set(ctx, gd, detector_id, name, location, unicode_tag_value)
    ip_set_id = resp["IpSetId"]
    ctx.on_cleanup(lambda: gd.delete_ip_set(DetectorId=detector_id, IpSetId=ip_set_id))

    got = gd.get_ip_set(DetectorId=detector_id, IpSetId=ip_set_id)
    assert got["Name"] == name, (got["Name"], name)
    assert got["Location"] == location, (got["Location"], location)
    assert got["Tags"]["note"] == unicode_tag_value, (got["Tags"], unicode_tag_value)

    listed = gd.list_ip_sets(DetectorId=detector_id)["IpSetIds"]
    assert ip_set_id in listed, (ip_set_id, listed)


def _ensure_detector(ctx, gd) -> str:
    try:
        detector_id = gd.create_detector(Enable=True)["DetectorId"]
        ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))
        return detector_id
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "BadRequestException":
            raise
        existing = gd.list_detectors().get("DetectorIds", [])
        if not existing:
            raise
        return existing[0]


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))


def _allow_guardduty_read(s3, bucket: str, key: str, account_id: str, detector_arn: str) -> None:
    """GuardDuty fetches IPSet content using its own service-linked role
    (AWSServiceRoleForAmazonGuardDuty), not the caller's credentials -- the
    bucket must explicitly grant that service principal s3:GetObject on the
    exact object, scoped to this account/detector, or CreateIPSet fails with
    an InternalServerErrorException while validating the file."""
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
                    "StringEquals": {
                        "aws:SourceAccount": account_id,
                        "aws:SourceArn": detector_arn,
                    }
                },
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def _retry_create_ip_set(ctx, gd, detector_id: str, name: str, location: str, tag_value: str, timeout_s: float = 60.0):
    """The bucket policy granting GuardDuty's service-linked role read access
    can take a few seconds to propagate; retry CreateIPSet across that
    window instead of failing on the first attempt."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return gd.create_ip_set(
                DetectorId=detector_id,
                Name=name,
                Format="TXT",
                Location=location,
                Activate=False,
                Tags={"note": tag_value},
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InternalServerErrorException":
                raise
            last_exc = exc
            time.sleep(5.0)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

