"""format-conversion-error-code-distinguishes-malformed-data-from-parse-error."""
from __future__ import annotations

import base64
import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "format-conversion-error-code-distinguishes-malformed-data-from-parse-error"

GROUP = "delivery-format"

SERVICES = ["firehose", "glue", "s3"]


_COLUMNS = [
    {"Name": "marker", "Type": "string"},
    {"Name": "n", "Type": "int"},
    {"Name": "tags", "Type": "array<struct<sku:string,qty:int>>"},
]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"sim2real-xsvc-{kind}-")


def _delete_bucket(ctx, bucket: str) -> None:
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
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = _xname(ctx, "bkt")
    params: dict[str, Any] = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(ctx, name))
    return name


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _firehose_role(ctx, *, bucket_arn: str) -> dict[str, str]:
    iam = ctx.client("iam")
    role_name = _xname(ctx, "role-firehose")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "firehose.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    policy = {
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
                ],
                "Resource": [bucket_arn, f"{bucket_arn}/*"],
            },
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
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(policy))
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _glue_name(ctx, kind: str) -> str:
    return _xname(ctx, kind).replace("-", "_")


def _create_glue_table(ctx, columns: list[dict[str, str]]) -> dict[str, str]:
    glue = ctx.client("glue")
    db = _glue_name(ctx, "db")
    glue.create_database(DatabaseInput={"Name": db})
    ctx.on_cleanup(lambda: _try(lambda: glue.delete_database(Name=db)))
    table = _glue_name(ctx, "tbl")
    glue.create_table(
        DatabaseName=db,
        TableInput={
            "Name": table,
            "TableType": "EXTERNAL_TABLE",
            "Parameters": {"classification": "parquet", "EXTERNAL": "TRUE"},
            "StorageDescriptor": {
                "Columns": columns,
                "Location": "s3://sim2real-placeholder/pq/",
                "InputFormat": "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": (
                        "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
                    )
                },
            },
        },
    )
    ctx.on_cleanup(lambda: _try(lambda: glue.delete_table(DatabaseName=db, Name=table)))
    return {"database": db, "table": table}


def _try(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "EntityNotFoundException",
            "ResourceNotFoundException",
        ):
            raise


def _create_stream(ctx, *, role_arn, bucket_arn, schema):
    firehose = ctx.client("firehose")
    name = _xname(ctx, "dstream")
    dest = {
        "RoleARN": role_arn,
        "BucketARN": bucket_arn,
        "Prefix": "pq/",
        "ErrorOutputPrefix": "err/!{firehose:error-output-type}/",
        "BufferingHints": {"SizeInMBs": 64, "IntervalInSeconds": 60},
        "CompressionFormat": "UNCOMPRESSED",
        "DataFormatConversionConfiguration": {
            "Enabled": True,
            "InputFormatConfiguration": {"Deserializer": {"OpenXJsonSerDe": {}}},
            "OutputFormatConfiguration": {
                "Serializer": {"ParquetSerDe": {"Compression": "UNCOMPRESSED"}}
            },
            "SchemaConfiguration": {
                "RoleARN": role_arn,
                "DatabaseName": schema["database"],
                "TableName": schema["table"],
                "Region": ctx.region,
                "VersionId": "LATEST",
            },
        },
    }
    deadline = time.monotonic() + 180
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=dest,
            )
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
        lambda: _try(
            lambda: ctx.client("firehose").delete_delivery_stream(
                DeliveryStreamName=name, AllowForceDelete=True
            )
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
    s3 = ctx.client("s3")
    keys: list[str] = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags(
    "axis:negative-delivery",
"cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:data", "timing:real-time",
)
def run(ctx) -> None:
    """A schema-type mismatch nested in an array of structs fails Parquet conversion as
    `DataFormatConversion.MalformedData` and unparseable JSON as `DataFormatConversion.ParseError`,
    both under the error prefix with `rawData` recoverable, while a conforming sibling lands."""
    bucket = _new_bucket(ctx)
    bucket_arn = f"arn:aws:s3:::{bucket}"
    schema = _create_glue_table(ctx, _COLUMNS)
    role = _firehose_role(ctx, bucket_arn=bucket_arn)
    firehose, stream = _create_stream(ctx, role_arn=role["arn"], bucket_arn=bucket_arn, schema=schema)

    good_marker = ctx.unique_name("pqgood-")
    good_record = (
        json.dumps(
            {"marker": good_marker, "n": 1, "tags": [{"sku": "a", "qty": 1}]}, sort_keys=True
        )
        + "\n"
    ).encode("utf-8")
    # The ONE thing broken in this record: a string where the schema's NESTED array-of-struct
    # column declares an int. Everything else about it (marker, n, outer shape) is well-formed.
    mismatch_marker = ctx.unique_name("pqmismatch-")
    mismatch_record = (
        json.dumps(
            {
                "marker": mismatch_marker,
                "n": 2,
                "tags": [{"sku": "b", "qty": "not-an-int"}],
            },
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    unparseable_marker = ctx.unique_name("pqunparseable-")
    unparseable_record = f"not-json-at-all {unparseable_marker}\n".encode("utf-8")

    batch = _put_batch_with_retry(
        ctx, firehose, stream, [good_record, mismatch_record, unparseable_record]
    )
    assert batch["FailedPutCount"] == 0, (
        f"PutRecordBatch must accept all three records regardless of convertibility: {batch!r}"
    )

    s3 = ctx.client("s3")
    pq_keys = _poll_until(
        lambda: _list_keys(ctx, bucket, "pq/"),
        lambda ks: len(ks) > 0,
        timeout_s=420,
        interval_s=10,
        description="a converted Parquet object lands under pq/",
    )
    assert len(pq_keys) == 1, f"expected one converted object, got {sorted(pq_keys)!r}"
    delivered = s3.get_object(Bucket=bucket, Key=pq_keys[0])["Body"].read()
    assert good_marker.encode("utf-8") in delivered, (
        f"the conforming record is absent from the Parquet object: {good_marker!r}"
    )
    for bad_marker in (mismatch_marker, unparseable_marker):
        assert bad_marker.encode("utf-8") not in delivered, (
            f"a record that should have been diverted to the error prefix was written into the "
            f"Parquet object instead: {bad_marker!r}"
        )

    # Both diverted records land as separate LINES inside the SAME newline-delimited error object
    # for the window, not as one object each.
    err_keys = _poll_until(
        lambda: _list_keys(ctx, bucket, "err/"),
        lambda ks: len(ks) >= 1,
        timeout_s=300,
        interval_s=10,
        description="the unconvertible records land under the error prefix",
    )
    assert len(err_keys) == 1, (
        f"expected the two bad records to share one newline-delimited error object for this "
        f"flush window, got {sorted(err_keys)!r}"
    )
    key = err_keys[0]
    last_segment = key.rsplit("/", 1)[-1]
    assert "." not in last_segment, (
        f"error object key {key!r} carries a file extension; a format-conversion-failed "
        f"object must not"
    )
    lines = [
        line for line in s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8").splitlines()
        if line.strip()
    ]
    assert len(lines) == 2, (
        f"expected exactly two error lines (one per bad record), got {len(lines)}: {lines!r}"
    )

    docs_by_marker: dict[str, dict] = {}
    for line in lines:
        err_doc = json.loads(line)
        raw = base64.b64decode(err_doc["rawData"])
        if mismatch_marker.encode("utf-8") in raw:
            docs_by_marker["mismatch"] = err_doc
        elif unparseable_marker.encode("utf-8") in raw:
            docs_by_marker["unparseable"] = err_doc
        else:
            raise AssertionError(f"error line {line!r} rawData matched neither bad record")

    assert set(docs_by_marker) == {"mismatch", "unparseable"}, (
        f"expected one error object per bad record, got {sorted(docs_by_marker)!r}"
    )
    mismatch_doc = docs_by_marker["mismatch"]
    unparseable_doc = docs_by_marker["unparseable"]
    assert mismatch_doc["lastErrorCode"] == "DataFormatConversion.MalformedData", (
        f"a schema-type mismatch nested inside an array of structs must be lastErrorCode "
        f"DataFormatConversion.MalformedData, got {mismatch_doc.get('lastErrorCode')!r}: "
        f"{mismatch_doc!r}"
    )
    assert unparseable_doc["lastErrorCode"] == "DataFormatConversion.ParseError", (
        f"a record that is not parseable JSON at all must be lastErrorCode "
        f"DataFormatConversion.ParseError, got {unparseable_doc.get('lastErrorCode')!r}: "
        f"{unparseable_doc!r}"
    )
    assert mismatch_doc["lastErrorCode"] != unparseable_doc["lastErrorCode"], (
        "a parse failure and a type-mismatch failure must not share one error code"
    )
    assert base64.b64decode(mismatch_doc["rawData"]) == mismatch_record, (
        f"rawData for the mismatch record decoded to "
        f"{base64.b64decode(mismatch_doc['rawData'])!r}, expected the ORIGINAL pre-conversion "
        f"bytes {mismatch_record!r}"
    )
    assert base64.b64decode(unparseable_doc["rawData"]) == unparseable_record, (
        f"rawData for the unparseable record decoded to "
        f"{base64.b64decode(unparseable_doc['rawData'])!r}, expected the ORIGINAL bytes "
        f"{unparseable_record!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
