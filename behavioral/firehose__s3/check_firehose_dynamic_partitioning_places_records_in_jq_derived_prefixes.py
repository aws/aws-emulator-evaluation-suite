"""firehose-dynamic-partitioning-places-records-in-jq-derived-prefixes."""

from __future__ import annotations

import base64
import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firehose-dynamic-partitioning-places-records-in-jq-derived-prefixes"

GROUP = "partitioning"

SERVICES = ['firehose', 's3']



# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/APIReference/API_BufferingHints.html
@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "cap:c1", "timing:real-time")
def run(ctx) -> None:
    """Dynamic partitioning with an inline jq query routes three records with three `tenant` values
    into three S3 prefixes named by them; a record with no `tenant` lands under the error prefix
    with its original bytes.
    """
    bucket = _new_bucket(ctx)
    bucket_arn = f"arn:aws:s3:::{bucket}"
    role = _firehose_role(ctx, bucket_arn=bucket_arn)
    firehose, stream = _create_stream(
        ctx,
        role_arn=role["arn"],
        bucket_arn=bucket_arn,
        prefix="data/!{partitionKeyFromQuery:tenant}/",
        error_prefix="err/!{firehose:error-output-type}/",
        extra={
            # Dynamic partitioning requires BufferingHints.SizeInMBs >= 64; four small records
            # never reach it, so the 60 s interval still triggers the flush.
            "BufferingHints": {"SizeInMBs": 64, "IntervalInSeconds": 60},
            "DynamicPartitioningConfiguration": {"Enabled": True},
            "ProcessingConfiguration": {
                "Enabled": True,
                "Processors": [
                    {
                        "Type": "MetadataExtraction",
                        "Parameters": [
                            {
                                "ParameterName": "MetadataExtractionQuery",
                                "ParameterValue": "{tenant:.tenant}",
                            },
                            {"ParameterName": "JsonParsingEngine", "ParameterValue": "JQ-1.6"},
                        ],
                    }
                ],
            },
        },
    )

    tenants = ["alpha", "bravo", "charlie"]
    markers = {t: ctx.unique_name(f"part-{t}-") for t in tenants}
    orphan = ctx.unique_name("part-orphan-")
    records = [
        (json.dumps({"tenant": t, "marker": markers[t]}, sort_keys=True) + "\n").encode("utf-8")
        for t in tenants
    ]
    records.append((json.dumps({"marker": orphan}, sort_keys=True) + "\n").encode("utf-8"))
    resp = _put_batch_with_retry(ctx, firehose, stream, records)
    assert resp["FailedPutCount"] == 0, f"PutRecordBatch reported failures: {resp!r}"

    want = {f"data/{t}/" for t in tenants}
    keys = _poll_until(
        lambda: _list_keys(ctx, bucket, "data/"),
        lambda ks: _prefixes(ks) >= want,
        timeout_s=420,
        interval_s=10,
        description=f"three partitioned prefixes {sorted(want)!r} appear",
    )
    prefixes = _prefixes(keys)
    assert prefixes == want, (
        f"delivered prefixes were {sorted(prefixes)!r}, expected {sorted(want)!r}"
    )
    assert not [k for k in keys if "!{" in k], (
        f"an unresolved partition-key expression was used as a literal key: {sorted(keys)!r}"
    )

    s3 = ctx.client("s3")
    per_prefix: dict[str, list[str]] = {}
    for k in keys:
        raw = s3.get_object(Bucket=bucket, Key=k)["Body"].read()
        pfx = k[: k.index("/", len("data/")) + 1]
        per_prefix.setdefault(pfx, []).extend(
            json.loads(line)["marker"] for line in raw.splitlines() if line.strip()
        )
    expected_per_prefix = {f"data/{t}/": [markers[t]] for t in tenants}
    assert per_prefix == expected_per_prefix, (
        f"records were mis-routed: {per_prefix!r} vs {expected_per_prefix!r}"
    )

    err_keys = _poll_until(
        lambda: _list_keys(ctx, bucket, "err/"),
        lambda ks: len(ks) > 0,
        timeout_s=300,
        interval_s=10,
        description="the record with no tenant field lands under the error prefix",
    )
    assert len(err_keys) == 1, f"expected one error object, got {sorted(err_keys)!r}"
    err_key = err_keys[0]
    # A metadata-extraction failure evaluates firehose:error-output-type to
    # `metadata-extraction-failed`, a value the s3-prefixes documentation does not list.
    assert err_key.startswith("err/metadata-extraction-failed/"), (
        f"the error object key did not carry the metadata-extraction-failed error-output-type: "
        f"{err_key!r}"
    )
    err_doc = json.loads(s3.get_object(Bucket=bucket, Key=err_key)["Body"].read())
    assert err_doc["errorCode"] == "DynamicPartitioning.MetadataExtractionFailed", (
        f"the error object reported {err_doc.get('errorCode')!r}: {err_doc!r}"
    )
    # The error object carries the original record base64-encoded in `rawData`.
    assert base64.b64decode(err_doc["rawData"]) == records[-1], (
        f"rawData decoded to {base64.b64decode(err_doc['rawData'])!r}, expected the original "
        f"unroutable record {records[-1]!r}"
    )
    assert orphan not in json.dumps(per_prefix), (
        f"the unroutable record was placed in a data/ prefix anyway: {per_prefix!r}"
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


def _prefixes(keys: list[str]) -> set[str]:
    """The `data/<tenant>/` prefix of every delivered key,, parsed on the delimiter boundary
    rather than by splitting the whole key."""
    out = set()
    for k in keys:
        i = k.index("/", len("data/"))
        out.add(k[: i + 1])
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
