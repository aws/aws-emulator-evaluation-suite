"""concurrent-update-destination-race."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-update-destination-race"
GROUP = 'update-destination'
SERVICES = ['firehose']

TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}

ACCESS_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:AbortMultipartUpload",
                "s3:GetBucketLocation",
                "s3:GetObject",
                "s3:ListBucket",
                "s3:ListBucketMultipartUploads",
                "s3:PutObject",
                "kms:Decrypt",
                "kms:GenerateDataKey",
                "logs:PutLogEvents",
            ],
            "Resource": "*",
        }
    ],
}

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

def _bucket_arn(bucket_name):
    return f"arn:aws:s3:::{bucket_name}"

def _describe(ctx, name):
    return ctx.client("firehose").describe_delivery_stream(DeliveryStreamName=name)[
        "DeliveryStreamDescription"
    ]

def _delivery_role_arn(ctx):
    """Create a real IAM role Firehose can assume (validated at CreateDeliveryStream
    time, so a fabricated ARN is not usable); register its teardown."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-fh-role-")
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        Description="SimParityProbe behavioral fixture role",
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
    )
    iam.put_role_policy(
        RoleName=name,
        PolicyName="firehose-destination-access",
        PolicyDocument=json.dumps(ACCESS_POLICY),
    )

    def _teardown():
        try:
            for pn in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
                try:
                    iam.delete_role_policy(RoleName=name, PolicyName=pn)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchEntity":
                        raise
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_teardown)
    return resp["Role"]["Arn"]

def _make_bucket(ctx):
    """Create an S3 destination bucket and register its (empty-then-delete) teardown."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-firehose-dst-")
    kwargs = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        # us-east-1 is the historical default region and rejects an explicit
        # LocationConstraint pointed at itself; every other region requires one.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "purpose", "Value": "behavioral-check"}]}
    )

    def _teardown():
        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=name):
                for obj in page.get("Contents", []):
                    s3.delete_object(Bucket=name, Key=obj["Key"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        try:
            s3.delete_bucket(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_teardown)
    return name

def _default_s3_config(ctx, bucket_name):
    return {
        "RoleARN": _delivery_role_arn(ctx),
        "BucketARN": _bucket_arn(bucket_name),
        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
    }

#: Bound for a deleted delivery stream to answer not-found, inside the suite's cleanup budget.
_STREAM_DELETE_S = 300.0


def _delete_stream(ctx, name):
    """Delete the stream, retrying while it is still CREATING, and poll every 2 s until it is not found."""
    fh = ctx.client("firehose")
    deadline = time.monotonic() + _STREAM_DELETE_S
    deleted = False
    while True:
        status = None
        try:
            if not deleted:
                fh.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
                deleted = True
            status = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"][
                "DeliveryStreamStatus"
            ]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException":
                raise
        if status == "DELETING_FAILED":
            raise AssertionError(f"delivery stream {name} entered DELETING_FAILED")
        if time.monotonic() >= deadline:
            raise AssertionError(f"delivery stream {name} still present {_STREAM_DELETE_S:.0f} s after DeleteDeliveryStream")
        time.sleep(2)

def _create_stream(ctx, name, bucket_name=None, **extra):
    """Create a delivery stream with a minimal ExtendedS3 destination unless the
    caller supplies their own destination kwargs. Retries while the IAM role is
    still propagating (Firehose rejects a brand-new role until it is visible)."""
    fh = ctx.client("firehose")
    if bucket_name is None and not any(
        k.endswith("DestinationConfiguration") for k in extra
    ):
        bucket_name = _make_bucket(ctx)
    kwargs = {"DeliveryStreamName": name}
    if bucket_name is not None:
        kwargs["ExtendedS3DestinationConfiguration"] = _default_s3_config(ctx, bucket_name)
    kwargs.update(extra)

    deadline = time.monotonic() + 60
    while True:
        try:
            resp = fh.create_delivery_stream(**kwargs)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = (exc.response.get("Error", {}).get("Message") or "").lower()
            propagating = code == "InvalidArgumentException" and (
                "assume" in msg or "not authorized" in msg or "does not exist" in msg
            )
            if propagating and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_stream(ctx, name))
    return resp

def _wait_active(ctx, name, timeout_s=100, interval_s=3):
    return _poll_until(
        lambda: _describe(ctx, name),
        lambda d: d["DeliveryStreamStatus"] == "ACTIVE",
        timeout_s=timeout_s,
        interval_s=interval_s,
    )

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent UpdateDestination calls sharing one CurrentDeliveryStreamVersionId
    resolve via optimistic locking: exactly one racer wins and advances the
    VersionId; every loser fails with ConcurrentModificationException."""
    fh = ctx.client("firehose")
    name = ctx.unique_name("sim2real-behav-fh-race-")
    _create_stream(ctx, name, Tags=[{"Key": "purpose", "Value": "behavioral-check"}])
    _wait_active(ctx, name)

    desc = _describe(ctx, name)
    version = desc["VersionId"]
    dest_id = desc["Destinations"][0]["DestinationId"]

    def attempt(i):
        try:
            fh.update_destination(
                DeliveryStreamName=name,
                CurrentDeliveryStreamVersionId=version,
                DestinationId=dest_id,
                S3DestinationUpdate={"BufferingHints": {"SizeInMBs": 5 + i, "IntervalInSeconds": 60 + i}},
            )
            return (True, None, None)
        except ClientError as exc:
            return (False, exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", ""))

    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(attempt, range(5)))

    winners = [r for r in results if r[0]]
    error_codes = [r[1] for r in results if not r[0]]

    assert len(winners) == 1, f"exactly one racer should win the optimistic lock, got {len(winners)}"
    assert all(code == "ConcurrentModificationException" for code in error_codes), (
        f"all losing racers must fail with ConcurrentModificationException, got {error_codes}"
    )
    assert len(error_codes) == 4, f"expected 4 losing racers out of 5, got {len(error_codes)}: {results}"
    # The current version id a loser reads depends on whether the winner has committed, so only it is left open.
    prefix = f"Cannot update firehose: {name} since the current version id: "
    suffix = f" and specified version id: {version} do not match"
    for won, _code, message in results:
        if not won:
            assert message.startswith(prefix) and message.endswith(suffix), message

    desc2 = _describe(ctx, name)
    assert desc2["VersionId"] != version, "the single winning update must have advanced the VersionId"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
