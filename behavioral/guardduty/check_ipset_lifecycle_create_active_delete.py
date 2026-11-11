"""ipset-lifecycle-create-active-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ipset-lifecycle-create-active-delete"
GROUP = "state-machine"
SERVICES = ["guardduty"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """CreateIPSet reaches ACTIVE via GetIPSet; after DeleteIPSet, GetIPSet reports
    DELETE_PENDING or DELETED."""
    gd = ctx.client("guardduty")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    detector_id, _ = _get_or_create_detector(ctx)
    detector_arn = f"arn:aws:guardduty:{ctx.region}:{account_id}:detector/{detector_id}"
    bucket, key = _make_list_bucket(ctx, ["192.0.2.0/24"])
    _grant_guardduty_s3_read(ctx, bucket, key, account_id, detector_arn)

    name = ctx.unique_name("sim2real-ipset-")[:64]
    resp = gd.create_ip_set(
        DetectorId=detector_id,
        Name=name,
        Format="TXT",
        Location=f"s3://{bucket}/{key}",
        Activate=True,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-ipset"},
    )
    ip_set_id = resp["IpSetId"]
    ctx.on_cleanup(lambda: _safe_delete_ip_set(gd, detector_id, ip_set_id))

    status = _poll_until(
        lambda: gd.get_ip_set(DetectorId=detector_id, IpSetId=ip_set_id)["Status"],
        lambda s: s in ("ACTIVE", "ERROR"),
        timeout_s=120,
        interval_s=5,
    )
    assert status == "ACTIVE", f"expected ACTIVE, got {status}"

    gd.delete_ip_set(DetectorId=detector_id, IpSetId=ip_set_id)

    # GuardDuty documents that activate/deactivate/delete for IP address lists complete
    # asynchronously and can take up to ~40 minutes end-to-end. Rather than block for that
    # long, assert the bounded, immediately-observable part of the contract: the delete
    # request is accepted and the resource transitions out of ACTIVE into a deletion-in-
    # progress state (DELETE_PENDING), or DELETED once the deletion completes.
    result = _poll_delete_initiated(
        lambda: gd.get_ip_set(DetectorId=detector_id, IpSetId=ip_set_id),
        timeout_s=180,
        interval_s=5,
    )
    assert result in ("DELETE_PENDING", "DELETED"), (
        f"expected GetIPSet to report DELETE_PENDING or DELETED after delete, got {result}"
    )


# ===== helpers =====


def _get_or_create_detector(ctx):
    gd = ctx.client("guardduty")
    existing = gd.list_detectors().get("DetectorIds", [])
    if existing:
        return existing[0], False
    resp = gd.create_detector(
        Enable=True,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-ipset"},
    )
    detector_id = resp["DetectorId"]
    ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))
    return detector_id, True


def _make_list_bucket(ctx, lines):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-gd-list-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    key = "list.txt"
    body = ("\n".join(lines) + "\n").encode()
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    return bucket, key


def _grant_guardduty_s3_read(ctx, bucket, key, account_id, detector_arn):
    # GuardDuty's service-linked role (AWSServiceRoleForAmazonGuardDuty) is protected and
    # cannot be modified directly via iam:PutRolePolicy on real AWS (UnmodifiableEntityException).
    # Grant read access via a resource-based S3 bucket policy naming the guardduty.amazonaws.com
    # service principal instead, scoped to this account/detector -- the same mechanism GuardDuty
    # publishing destinations use.
    s3 = ctx.client("s3")
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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


def _wait_for_error_code(call, *, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            call()
        except ClientError as e:
            return e.response["Error"]["Code"]
        time.sleep(interval_s)
    raise AssertionError(f"call never failed within {timeout_s}s (last_code={last_code})")


def _poll_delete_initiated(get_call, *, timeout_s=180.0, interval_s=5.0):
    """After Delete*, poll the Get* call until it reports the DELETE_PENDING or DELETED status of
    the asynchronous deletion; return the last status seen."""
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        last_status = get_call().get("Status")
        if last_status in ("DELETE_PENDING", "DELETED"):
            return last_status
        time.sleep(interval_s)
    return last_status


def _safe_delete_ip_set(gd, detector_id, ip_set_id):
    try:
        gd.delete_ip_set(DetectorId=detector_id, IpSetId=ip_set_id)
    except ClientError as exc:
        # GuardDuty reports an IPSet that is already gone as BadRequestException.
        if exc.response["Error"]["Code"] != "BadRequestException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
