"""trustedentityset-lifecycle-create-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trustedentityset-lifecycle-create-delete"
GROUP = "state-machine"
SERVICES = ["guardduty"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """CreateTrustedEntitySet is immediately retrievable (Status ACTIVATING/ACTIVE), and
    DeleteTrustedEntitySet visibly starts removing it (an immediate not-found, or a
    DELETE_PENDING/DELETED status); the full ACTIVE transition can take up to ~40 minutes."""
    gd = ctx.client("guardduty")
    detector_id, _ = _get_or_create_detector(ctx)
    bucket, key = _make_list_bucket(ctx, ["trusted.example.com", "198.51.100.42"])

    name = ctx.unique_name("sim2real-trs-")[:64]
    resp = gd.create_trusted_entity_set(
        DetectorId=detector_id,
        Name=name,
        Format="TXT",
        Location=f"s3://{bucket}/{key}",
        Activate=True,
    )
    entity_set_id = resp["TrustedEntitySetId"]
    ctx.on_cleanup(lambda: _safe_delete(gd, detector_id, entity_set_id))

    got = gd.get_trusted_entity_set(DetectorId=detector_id, TrustedEntitySetId=entity_set_id)
    assert got["Name"] == name, f"expected Name {name!r}, got {got['Name']!r}"
    assert got["Status"] in ("ACTIVATING", "ACTIVE"), f"unexpected initial status {got['Status']}"

    try:
        gd.delete_trusted_entity_set(DetectorId=detector_id, TrustedEntitySetId=entity_set_id)
    except ClientError as err:
        # Deleting while the resource is still ACTIVATING is itself a documented, valid
        # state-machine rejection ("can't perform any action" while Activating).
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message")
        assert code == "ConflictException", (
            f"expected ConflictException when deleting a still-ACTIVATING resource, got {code}"
        )
        expected = "Another operation is currently in progress, please wait until it completes, then try again."
        assert message == expected, f"expected message {expected!r}, got {message!r}"
        return

    result = _poll_delete_initiated(
        lambda: gd.get_trusted_entity_set(
            DetectorId=detector_id, TrustedEntitySetId=entity_set_id
        ),
        timeout_s=120,
        interval_s=5,
    )
    assert result in ("DELETE_PENDING", "DELETED", "BadRequestException"), (
        f"expected DELETE_PENDING/DELETED status or BadRequestException after delete, got {result}"
    )


# ===== helpers =====


def _get_or_create_detector(ctx):
    gd = ctx.client("guardduty")
    existing = gd.list_detectors().get("DetectorIds", [])
    if existing:
        return existing[0], False
    resp = gd.create_detector(Enable=True)
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
    """After Delete*, the resource should either already be gone (ClientError) or report
    a DELETE_PENDING/DELETED status reflecting the in-progress (or completed) async deletion.
    Returns the observed status string, or the ClientError code if unretrievable."""
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            resp = get_call()
            last_status = resp.get("Status")
            if last_status in ("DELETE_PENDING", "DELETED"):
                return last_status
        except ClientError as e:
            return e.response["Error"]["Code"]
        time.sleep(interval_s)
    return last_status


def _safe_delete(gd, detector_id, entity_set_id):
    try:
        gd.delete_trusted_entity_set(DetectorId=detector_id, TrustedEntitySetId=entity_set_id)
    except ClientError as exc:
        # GuardDuty reports a TrustedEntitySet that is already gone as BadRequestException.
        if exc.response["Error"]["Code"] != "BadRequestException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
