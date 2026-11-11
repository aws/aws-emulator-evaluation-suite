"""firehose-destination-repointed-mid-stream-and-the-differential-barrier-proves-the-switch."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firehose-destination-repointed-mid-stream-and-the-differential-barrier-proves-the-switch"

GROUP = "state-machine"

SERVICES = ['firehose', 's3']



# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/APIReference/API_BufferingHints.html
@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "cap:c1", "timing:real-time")
def run(ctx) -> None:
    """After UpdateDestination repoints a live stream at a second bucket, records put afterwards land
    only in the new bucket and the record put before the change stays only in the old one.
    """
    old_bucket = _new_bucket(ctx, "old")
    new_bucket = _new_bucket(ctx, "new")
    old_arn = f"arn:aws:s3:::{old_bucket}"
    new_arn = f"arn:aws:s3:::{new_bucket}"
    role = _firehose_role(
        ctx,
        bucket_arn=old_arn,
        extra_statements=[
            {
                "Effect": "Allow",
                "Action": _S3_DELIVERY_ACTIONS,
                "Resource": [new_arn, f"{new_arn}/*"],
            }
        ],
    )
    firehose, stream = _create_stream(
        ctx, role_arn=role["arn"], bucket_arn=old_arn, prefix="p/"
    )

    p1 = ctx.unique_name("pre-")
    _put_record_with_retry(ctx, firehose, stream, _rec(p1))
    old_markers = _poll_until(
        lambda: _markers(ctx, old_bucket, "p/"),
        lambda ms: p1 in ms,
        timeout_s=420,
        interval_s=10,
        description=f"the barrier record {p1!r} is delivered to the ORIGINAL bucket",
    )
    assert p1 in old_markers, (
        f"P1 never arrived in the original bucket ({sorted(old_markers)!r}), so nothing "
        f"downstream of the destination change can be concluded"
    )

    desc_before = firehose.describe_delivery_stream(DeliveryStreamName=stream)[
        "DeliveryStreamDescription"
    ]
    version_before = desc_before["VersionId"]
    destination_id = desc_before["Destinations"][0]["DestinationId"]
    firehose.update_destination(
        DeliveryStreamName=stream,
        CurrentDeliveryStreamVersionId=version_before,
        DestinationId=destination_id,
        ExtendedS3DestinationUpdate={
            "RoleARN": role["arn"],
            "BucketARN": new_arn,
            "Prefix": "p/",
            "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
            "CompressionFormat": "UNCOMPRESSED",
        },
    )
    desc_after = _poll_until(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=stream)[
            "DeliveryStreamDescription"
        ],
        lambda d: d["Destinations"][0]
        .get("ExtendedS3DestinationDescription", {})
        .get("BucketARN")
        == new_arn
        and d["DeliveryStreamStatus"] == "ACTIVE",
        timeout_s=180,
        interval_s=5,
        description="the described destination becomes the new bucket and the stream is ACTIVE",
    )
    version_after = desc_after["VersionId"]
    assert version_after != version_before, (
        f"VersionId did not advance across UpdateDestination: {version_before!r}"
    )
    reported_arn = desc_after["Destinations"][0]["ExtendedS3DestinationDescription"]["BucketARN"]
    assert reported_arn == new_arn, (
        f"after UpdateDestination the stream reports destination {reported_arn!r}, "
        f"expected {new_arn!r}"
    )

    post = [ctx.unique_name("post-") for _ in range(3)]
    for marker in post:
        _put_record_with_retry(ctx, firehose, stream, _rec(marker))
    new_markers = _poll_until(
        lambda: _markers(ctx, new_bucket, "p/"),
        lambda ms: set(post) <= ms,
        timeout_s=420,
        interval_s=10,
        description=f"all three post-change records {post!r} reach the NEW bucket",
    )
    assert set(post) <= new_markers, (
        f"the new bucket holds {sorted(new_markers)!r}, missing "
        f"{sorted(set(post) - new_markers)!r}"
    )

    # Three sustained deliveries to the new bucket are the barrier (not a sleep): only now is the
    # old bucket's content evidence of an absence rather than of an unresolved race.
    old_final = _markers(ctx, old_bucket, "p/")
    assert not (set(post) & old_final), (
        f"post-change records leaked into the old bucket: {sorted(set(post) & old_final)!r}"
    )
    assert p1 in old_final and p1 not in new_markers, (
        f"the pre-change record must stay put: in old={p1 in old_final!r}, "
        f"in new={p1 in new_markers!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"

_S3_DELIVERY_ACTIONS = [
    "s3:AbortMultipartUpload",
    "s3:GetBucketLocation",
    "s3:GetObject",
    "s3:ListBucket",
    "s3:ListBucketMultipartUploads",
    "s3:PutObject",
]


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_bucket(ctx, bucket: str) -> None:
    """Empty a bucket (objects + versions + delete markers) then delete it. Teardown swallows
    exceptions, so a raw delete_bucket on a non-empty bucket would silently leak it."""
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            targets = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if targets:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": targets}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    _retry_teardown(lambda: s3.delete_bucket(Bucket=bucket))


def _retry_teardown(fn, *, attempts=4, interval_s=3.0) -> None:
    """Retry a teardown call; not-found means gone and the last failure raises."""
    for i in range(attempts):
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("NoSuchBucket", "NoSuchEntity", "ResourceNotFoundException"):
                return
            if i == attempts - 1:
                raise
            time.sleep(interval_s)


def _new_bucket(ctx, kind: str = "bkt") -> str:
    """Create a uniquely-named, region-correct, tagged bucket; register empty+delete teardown."""
    s3 = ctx.client("s3")
    name = _xname(ctx, kind)
    params: dict[str, Any] = {"Bucket": name}
    # us-east-1 is S3's default region and CreateBucket rejects an explicit LocationConstraint
    # for it; this follows ctx.region, it does not pin one.
    if ctx.region and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(ctx, name))
    try:
        s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    except ClientError:
        pass
    return name


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    _retry_teardown(lambda: iam.delete_role(RoleName=role_name))


def _create_role(ctx, trust_service: str, inline_policy: dict, kind: str) -> dict[str, str]:
    """Create a tagged IAM role under /sim2real/ and register its teardown immediately."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, kind)
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
    )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _firehose_role(ctx, *, bucket_arn, extra_statements=None) -> dict[str, str]:
    """The Firehose delivery role: S3 write on one bucket, plus whatever the destination needs."""
    statements = [
        {
            "Effect": "Allow",
            "Action": _S3_DELIVERY_ACTIONS,
            "Resource": [bucket_arn, f"{bucket_arn}/*"],
        }
    ]
    statements.extend(extra_statements or [])
    return _create_role(
        ctx,
        "firehose.amazonaws.com",
        {"Version": "2012-10-17", "Statement": statements},
        "role-firehose",
    )


def _create_stream(ctx, *, role_arn, bucket_arn, prefix, extra=None, error_prefix=None):
    """Create a DirectPut -> ExtendedS3 delivery stream and poll it to ACTIVE.

    Firehose ASSUMES the delivery role during CreateDeliveryStream, so a role created seconds ago
    loses the IAM propagation race with `InvalidArgumentException: ... unable to assume role`.
    That window is retried against a deadline rather than slept through.
    """
    firehose = ctx.client("firehose")
    name = _xname(ctx, "dstream")
    dest: dict[str, Any] = {
        "RoleARN": role_arn,
        "BucketARN": bucket_arn,
        "Prefix": prefix,
        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
        "CompressionFormat": "UNCOMPRESSED",
    }
    if error_prefix is not None:
        dest["ErrorOutputPrefix"] = error_prefix
    dest.update(extra or {})
    kwargs = dict(
        DeliveryStreamName=name,
        DeliveryStreamType="DirectPut",
        ExtendedS3DestinationConfiguration=dest,
        Tags=_xsvc_tags_kv(),
    )
    deadline = time.monotonic() + 120
    while True:
        try:
            firehose.create_delivery_stream(**kwargs)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = exc.response.get("Error", {}).get("Message", "")
            if (
                code == "InvalidArgumentException"
                and ("assume role" in msg.lower() or "not authorized" in msg.lower())
                and time.monotonic() < deadline
            ):
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(
        lambda: _retry_teardown(
            lambda: ctx.client("firehose").delete_delivery_stream(DeliveryStreamName=name)
        )
    )
    status = _poll_until(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"],
        lambda s: s in ("ACTIVE", "CREATING_FAILED"),
        timeout_s=300,
        interval_s=5,
        description=f"delivery stream {name} reaches ACTIVE",
    )
    assert status == "ACTIVE", f"delivery stream {name} became {status!r} instead of ACTIVE"
    return firehose, name


def _put_batch_with_retry(ctx, firehose, stream, records, *, timeout_s=180.0):
    """PutRecordBatch, retrying only the delivery-role propagation window at first use.

    A brand-new stream can reject the first put while the role it assumed is still converging.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return firehose.put_record_batch(
                DeliveryStreamName=stream, Records=[{"Data": r} for r in records]
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in (
                "AccessDeniedException",
                "AccessDenied",
                "ServiceUnavailableException",
                "ResourceNotFoundException",
            ) and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _list_keys(ctx, bucket: str, prefix: str) -> list[str]:
    """Every key under prefix, across all pages."""
    s3 = ctx.client("s3")
    keys: list[str] = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


def _rec(marker: str) -> bytes:
    return (json.dumps({"marker": marker}, sort_keys=True) + "\n").encode("utf-8")


def _markers(ctx, bucket: str, prefix: str) -> set[str]:
    """Every `marker` value delivered under prefix in the given bucket, read structurally."""
    s3 = ctx.client("s3")
    out = set()
    for key in sorted(_list_keys(ctx, bucket, prefix)):
        raw = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        for line in raw.splitlines():
            if line.strip():
                out.add(json.loads(line)["marker"])
    return out


def _put_record_with_retry(ctx, firehose, stream, data: bytes, *, timeout_s=180.0):
    """PutRecord, retrying only the delivery-role propagation window at first use of the role."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return firehose.put_record(DeliveryStreamName=stream, Record={"Data": data})
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in (
                "AccessDeniedException",
                "ServiceUnavailableException",
                "ResourceNotFoundException",
            ) and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
