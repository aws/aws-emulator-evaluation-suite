"""firehose-parquet-conversion-rejects-a-schema-mismatched-record-to-the-error-prefix."""

from __future__ import annotations

import base64
import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firehose-parquet-conversion-rejects-a-schema-mismatched-record-to-the-error-prefix"

GROUP = "delivery-format"

SERVICES = ['firehose', 'glue', 's3']



_COLUMNS = [
    {"Name": "marker", "Type": "string"},
    {"Name": "n", "Type": "int"},
    {"Name": "kind", "Type": "string"},
]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c1", "timing:real-time",
)
def run(ctx) -> None:
    """A record the Glue schema cannot deserialize goes to the format-conversion-failed error prefix,
    while the four conforming records in the same batch land as one Parquet object with the columns.
    """
    bucket = _new_bucket(ctx)
    bucket_arn = f"arn:aws:s3:::{bucket}"
    schema = _create_glue_table(ctx, _COLUMNS)
    role = _firehose_role(
        ctx,
        bucket_arn=bucket_arn,
        extra_statements=[
            {
                "Effect": "Allow",
                "Action": [
                    "glue:GetDatabase",
                    "glue:GetDatabases",
                    "glue:GetTable",
                    "glue:GetTables",
                    "glue:GetTableVersion",
                    "glue:GetTableVersions",
                ],
                "Resource": "*",
            }
        ],
    )
    firehose, stream = _create_stream(
        ctx,
        role_arn=role["arn"],
        bucket_arn=bucket_arn,
        prefix="pq/",
        error_prefix="err/!{firehose:error-output-type}/",
        extra={
            # Format conversion refuses SizeInMBs below 64; the 60 s interval still triggers flush.
            "BufferingHints": {"SizeInMBs": 64, "IntervalInSeconds": 60},
            "CompressionFormat": "UNCOMPRESSED",
            "DataFormatConversionConfiguration": {
                "Enabled": True,
                "InputFormatConfiguration": {"Deserializer": {"OpenXJsonSerDe": {}}},
                "OutputFormatConfiguration": {
                    "Serializer": {"ParquetSerDe": {"Compression": "UNCOMPRESSED"}}
                },
                "SchemaConfiguration": {
                    "RoleARN": role["arn"],
                    "DatabaseName": schema["database"],
                    "TableName": schema["table"],
                    "Region": ctx.region,
                    "VersionId": "LATEST",
                },
            },
        },
    )

    markers = [ctx.unique_name(f"pq{i}-") for i in range(4)]
    records = [
        (
            json.dumps({"marker": m, "n": i, "kind": "conforming"}, sort_keys=True) + "\n"
        ).encode("utf-8")
        for i, m in enumerate(markers)
    ]
    bad_marker = ctx.unique_name("pqbad-")
    bad_record = f"not-json-at-all {bad_marker}\n".encode("utf-8")
    batch = _put_batch_with_retry(ctx, firehose, stream, records + [bad_record])
    assert batch["FailedPutCount"] == 0, (
        f"PutRecordBatch must accept all five records regardless of convertibility: {batch!r}"
    )

    s3 = ctx.client("s3")
    # UNCOMPRESSED Parquet lets markers and column names be matched as literal UTF-8 bytes.
    pq_keys = _poll_until(
        lambda: _list_keys(ctx, bucket, "pq/"),
        lambda ks: len(ks) > 0,
        timeout_s=420,
        interval_s=10,
        description="a converted Parquet object lands under pq/",
    )
    assert len(pq_keys) == 1, f"expected one converted object, got {sorted(pq_keys)!r}"
    delivered = s3.get_object(Bucket=bucket, Key=pq_keys[0])["Body"].read()

    assert delivered[:4] == b"PAR1" and delivered[-4:] == b"PAR1", (
        f"the delivered object is not a Parquet file: head {delivered[:4]!r}, "
        f"tail {delivered[-4:]!r}"
    )
    missing_columns = [c["Name"] for c in _COLUMNS if c["Name"].encode("utf-8") not in delivered]
    assert missing_columns == [], (
        f"the Parquet schema does not name the Glue table columns {missing_columns!r}; "
        f"footer tail was {delivered[-256:]!r}"
    )
    missing_rows = [m for m in markers if m.encode("utf-8") not in delivered]
    assert missing_rows == [], (
        f"{len(missing_rows)!r} of 4 conforming records are absent from the Parquet object: "
        f"{missing_rows!r}"
    )
    assert bad_marker.encode("utf-8") not in delivered, (
        f"the unconvertible record was written into the Parquet object anyway: {bad_marker!r}"
    )
    assert b'"marker"' not in delivered, (
        f"the delivered object still contains the JSON key form, so no conversion happened: "
        f"{delivered[:120]!r}"
    )

    err_keys = _poll_until(
        lambda: _list_keys(ctx, bucket, "err/"),
        lambda ks: len(ks) > 0,
        timeout_s=300,
        interval_s=10,
        description="the unconvertible record lands under the error prefix",
    )
    assert len(err_keys) == 1, f"expected one error object, got {sorted(err_keys)!r}"
    err_key = err_keys[0]
    assert err_key.startswith("err/format-conversion-failed/"), (
        f"the error object key did not encode the format-conversion-failed error-output-type: "
        f"{err_key!r}"
    )
    err_doc = json.loads(s3.get_object(Bucket=bucket, Key=err_key)["Body"].read())
    assert base64.b64decode(err_doc["rawData"]) == bad_record, (
        f"rawData decoded to {base64.b64decode(err_doc['rawData'])!r}, expected the original "
        f"unconvertible record {bad_record!r}; whole error document was {err_doc!r}"
    )
    assert err_doc["dataCatalogTable"]["tableName"] == schema["table"], (
        f"the error object attributes the failure to {err_doc.get('dataCatalogTable')!r}, "
        f"expected table {schema['table']!r}"
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


_TEARDOWN_GONE = ("NoSuchBucket", "NoSuchEntity", "ResourceNotFoundException", "EntityNotFoundException")
_TEARDOWN_BUSY = (
    "ResourceInUseException", "ResourceConflictException", "ConcurrentModificationException",
    "DeleteConflict", "OperationAbortedException", "ThrottlingException", "Throttling",
    "TooManyRequestsException",
)


def _retry_teardown(fn, *, deadline_s=60.0) -> None:
    """Run a teardown delete: return when done or already gone, retry a busy or throttled
    refusal every 2 s up to deadline_s, raise everything else."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in _TEARDOWN_GONE:
                return
            if code not in _TEARDOWN_BUSY or time.monotonic() >= deadline:
                raise
            time.sleep(2)


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

    Firehose assumes the role during CreateDeliveryStream, so a fresh role is retried until it works.
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
    ctx.on_cleanup(lambda: _delete_stream(ctx, name))
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


def _delete_stream(ctx, name: str, timeout_s: float = 300.0) -> None:
    """DeleteDeliveryStream is asynchronous: the stream stays DELETING until it is gone."""
    firehose = ctx.client("firehose")
    _retry_teardown(lambda: firehose.delete_delivery_stream(DeliveryStreamName=name))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            firehose.describe_delivery_stream(DeliveryStreamName=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            return
        time.sleep(2)
    raise RuntimeError(f"delivery stream {name} still exists {timeout_s:.0f} s after DeleteDeliveryStream")


def _put_batch_with_retry(ctx, firehose, stream, records, *, timeout_s=180.0):
    """PutRecordBatch, retrying while a new stream's assumed role is still propagating."""
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
    """Every key under prefix, paginated."""
    s3 = ctx.client("s3")
    keys: list[str] = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


def _glue_name(ctx, kind: str) -> str:
    """A Glue-legal name: the catalog rejects '-', so the prefix is underscore-spelled."""
    return _xname(ctx, kind).replace("-", "_")


def _create_glue_table(ctx, columns: list[dict[str, str]]) -> dict[str, str]:
    """Create a Glue database + table describing the record schema; register both teardowns."""
    glue = ctx.client("glue")
    db = _glue_name(ctx, "db")
    glue.create_database(DatabaseInput={"Name": db, "Description": "sim2real-xsvc firehose parquet"})
    ctx.on_cleanup(lambda: _retry_teardown(lambda: ctx.client("glue").delete_database(Name=db)))
    table = _glue_name(ctx, "tbl")
    glue.create_table(
        DatabaseName=db,
        TableInput={
            "Name": table,
            "Description": "sim2real-xsvc firehose parquet target schema",
            "TableType": "EXTERNAL_TABLE",
            "Parameters": {"classification": "parquet", "sim2real:managed": "true"},
            "StorageDescriptor": {
                "Columns": columns,
                "Location": "s3://sim2real-xsvc-unused/",
                "InputFormat": "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat",
                "OutputFormat": (
                    "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"
                ),
                "SerdeInfo": {
                    "SerializationLibrary": (
                        "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
                    )
                },
            },
        },
    )
    ctx.on_cleanup(
        lambda: _retry_teardown(
            lambda: ctx.client("glue").delete_table(DatabaseName=db, Name=table)
        )
    )
    return {"database": db, "table": table}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
