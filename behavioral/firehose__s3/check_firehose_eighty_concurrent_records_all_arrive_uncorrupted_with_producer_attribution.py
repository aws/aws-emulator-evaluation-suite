"""firehose-eighty-concurrent-records-all-arrive-uncorrupted-with-producer-attribution."""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firehose-eighty-concurrent-records-all-arrive-uncorrupted-with-producer-attribution"

GROUP = "concurrency"

SERVICES = ['firehose', 's3']



_WORKERS = 8

_PER_WORKER = 10


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/APIReference/API_BufferingHints.html
@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "cap:c1", "timing:real-time")
def run(ctx) -> None:
    """Eighty records from eight concurrent producers all arrive in S3 with producer and ordinal
    intact, every line is one valid JSON object, and the eighty PutRecord calls return distinct
    RecordIds; line count is not asserted because Firehose delivery is at-least-once."""
    bucket = _new_bucket(ctx)
    bucket_arn = f"arn:aws:s3:::{bucket}"
    role = _firehose_role(ctx, bucket_arn=bucket_arn)
    firehose, stream = _create_stream(
        ctx, role_arn=role["arn"], bucket_arn=bucket_arn, prefix="c/"
    )
    run_id = ctx.unique_name("conc-")

    # One warm put first: it absorbs the delivery-role propagation window against a bounded
    # deadline, so the eight concurrent workers below race each other and not IAM.
    _put_record_with_retry(
        ctx, firehose, stream, json.dumps({"run": run_id, "warm": True}).encode() + b"\n"
    )

    def _producer(worker: int) -> list[str]:
        ids = []
        for ordinal in range(_PER_WORKER):
            payload = (
                json.dumps(
                    {"run": run_id, "worker": worker, "ordinal": ordinal}, sort_keys=True
                )
                + "\n"
            ).encode("utf-8")
            resp = firehose.put_record(DeliveryStreamName=stream, Record={"Data": payload})
            ids.append(resp["RecordId"])
        return ids

    record_ids: list[str] = []
    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        for ids in pool.map(_producer, range(_WORKERS)):
            record_ids.extend(ids)

    expected = {(w, o) for w in range(_WORKERS) for o in range(_PER_WORKER)}
    assert len(record_ids) == _WORKERS * _PER_WORKER, (
        f"{len(record_ids)!r} PutRecord calls returned a RecordId, expected "
        f"{_WORKERS * _PER_WORKER!r}"
    )
    assert len(set(record_ids)) == len(record_ids), (
        f"{len(record_ids)!r} puts returned only {len(set(record_ids))!r} distinct RecordIds"
    )

    parsed = _poll_until(
        lambda: _parse_delivered(ctx, bucket, "c/", run_id),
        lambda st: expected <= st["pairs"],
        timeout_s=420,
        interval_s=10,
        description=f"all {len(expected)!r} concurrently-produced records land in S3",
    )
    assert parsed["unparseable"] == [], (
        f"{len(parsed['unparseable'])!r} delivered lines were not a single valid JSON object; "
        f"first: {parsed['unparseable'][0]!r}"
    )
    assert parsed["pairs"] == expected, (
        f"missing {sorted(expected - parsed['pairs'])[:8]!r}, "
        f"unexpected {sorted(parsed['pairs'] - expected)[:8]!r}"
    )
    per_worker = {w: sorted(o for (ww, o) in parsed["pairs"] if ww == w) for w in range(_WORKERS)}
    assert per_worker == {w: list(range(_PER_WORKER)) for w in range(_WORKERS)}, (
        f"ordinals crossed producers: {per_worker!r}"
    )
    assert parsed["foreign"] == [], (
        f"lines from another run leaked into this run's prefix: {parsed['foreign'][:3]!r}"
    )


# ===== helpers =====
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
    # us-east-1 is CreateBucket's implicit default location; passing a LocationConstraint for it
    # is itself rejected, so the literal here is the S3 API contract, not an assumed region.
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


def _parse_delivered(ctx, bucket: str, prefix: str, run_id: str) -> dict[str, Any]:
    """Read every delivered object under prefix and classify every line.

    Returns the set of (worker, ordinal) pairs, the lines that are not a single valid JSON object
    (interleaving corruption), and any line carrying a different run id.
    """
    s3 = ctx.client("s3")
    pairs: set[tuple[int, int]] = set()
    unparseable: list[bytes] = []
    foreign: list[str] = []
    for key in sorted(_list_keys(ctx, bucket, prefix)):
        raw = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        for line in raw.splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                unparseable.append(line[:200])
                continue
            if not isinstance(rec, dict) or rec.get("run") != run_id:
                foreign.append(line[:200].decode("utf-8", "replace"))
                continue
            if rec.get("warm"):
                continue
            pairs.add((rec["worker"], rec["ordinal"]))
    return {"pairs": pairs, "unparseable": unparseable, "foreign": foreign}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
