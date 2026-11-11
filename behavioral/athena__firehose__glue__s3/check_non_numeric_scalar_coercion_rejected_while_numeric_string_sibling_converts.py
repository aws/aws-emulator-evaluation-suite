"""non-numeric-scalar-coercion-rejected-while-numeric-string-sibling-converts."""

from __future__ import annotations

import base64
import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "non-numeric-scalar-coercion-rejected-while-numeric-string-sibling-converts"

GROUP = "delivery-format"

SERVICES = ["athena", "firehose", "glue", "s3"]


_COLUMNS = [
    {"Name": "ticker", "Type": "string"},
    {"Name": "price", "Type": "double"},
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


def _try(fn, *, deadline_s=30.0, interval_s=2.0):
    """Run a delete: return on success or a not-found refusal, retry an in-use or throttled refusal
    every 2 s to a deadline, and raise anything else."""
    gone = ("NoSuchBucket", "NoSuchEntity", "EntityNotFoundException", "ResourceNotFoundException")
    busy = ("ResourceInUseException", "DeleteConflict", "ConcurrentModificationException",
            "ThrottlingException", "Throttling", "TooManyRequestsException")
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "")
            if code in gone or (code == "InvalidRequestException" and "not found" in error.get("Message", "").lower()):
                return
            if code not in busy or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


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
    _try(lambda: s3.delete_bucket(Bucket=bucket))


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
    _try(lambda: iam.delete_role(RoleName=role_name))


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


def _create_glue_table(ctx, columns: list[dict[str, str]], location: str) -> dict[str, str]:
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
                "Location": location,
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


def _create_workgroup(ctx, output_location: str) -> str:
    athena = ctx.client("athena")
    name = _xname(ctx, "wg")
    athena.create_work_group(
        Name=name,
        Configuration={
            "ResultConfiguration": {"OutputLocation": output_location},
            "PublishCloudWatchMetricsEnabled": False,
        },
    )
    ctx.on_cleanup(
        lambda: _try(
            lambda: ctx.client("athena").delete_work_group(WorkGroup=name, RecursiveDeleteOption=True)
        )
    )
    return name


def _create_stream(ctx, *, role_arn, bucket_arn, schema):
    firehose = ctx.client("firehose")
    name = _xname(ctx, "dstream")
    dest = {
        "RoleARN": role_arn,
        "BucketARN": bucket_arn,
        "Prefix": "main/",
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


def _put_batch(ctx, firehose, stream, records, *, timeout_s=180.0):
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


def _run_query(ctx, sql, database, workgroup, *, timeout_s=300.0):
    athena = ctx.client("athena")
    qid = athena.start_query_execution(
        QueryString=sql, QueryExecutionContext={"Database": database}, WorkGroup=workgroup
    )["QueryExecutionId"]
    state = _poll_until(
        lambda: athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"],
        lambda s: s["State"] in ("SUCCEEDED", "FAILED", "CANCELLED"),
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"Athena query {qid} reaches a terminal state",
    )
    return qid, state["State"], state.get("StateChangeReason")


def _select_rows(ctx, qid) -> list[list[str | None]]:
    athena = ctx.client("athena")
    rows: list[list[str | None]] = []
    for page in athena.get_paginator("get_query_results").paginate(QueryExecutionId=qid):
        for row in page["ResultSet"]["Rows"]:
            rows.append([d.get("VarCharValue") for d in row["Data"]])
    return rows[1:]


def _query_rows(ctx, sql, database, workgroup):
    qid, state, reason = _run_query(ctx, sql, database, workgroup)
    assert state == "SUCCEEDED", f"Athena query {qid} ended {state!r}: {reason!r} for sql {sql!r}"
    return qid, _select_rows(ctx, qid)


def _poll_rows(ctx, sql, database, workgroup, predicate, *, timeout_s=480.0, description="rows"):
    holder: dict[str, Any] = {}

    def probe():
        qid, rows = _query_rows(ctx, sql, database, workgroup)
        holder["qid"] = qid
        return rows

    rows = _poll_until(probe, predicate, timeout_s=timeout_s, interval_s=15.0, description=description)
    return holder["qid"], rows


def _list_keys(ctx, bucket, prefix) -> list[str]:
    s3 = ctx.client("s3")
    keys: list[str] = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/APIReference/API_BufferingHints.html
@tags(
    "axis:negative-delivery",
"cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A `double` column fed "2.5" reads back through Athena as 2.5, but "not-a-number" is rejected
    to the format-conversion-failed prefix as DataFormatConversion.MalformedData, not null or zero;
    the coercible sibling landing proves the bad record was rejected, not still in flight.
    """
    bucket = _new_bucket(ctx)
    bucket_arn = f"arn:aws:s3:::{bucket}"
    data_location = f"s3://{bucket}/main/"
    schema = _create_glue_table(ctx, _COLUMNS, data_location)
    workgroup = _create_workgroup(ctx, f"s3://{bucket}/athena-results/")
    role = _firehose_role(ctx, bucket_arn=bucket_arn)
    firehose, stream = _create_stream(ctx, role_arn=role["arn"], bucket_arn=bucket_arn, schema=schema)

    good_ticker = ctx.unique_name("good-")
    bad_ticker = ctx.unique_name("bad-")
    good_record = (json.dumps({"ticker": good_ticker, "price": "2.5"}, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    bad_record = (
        json.dumps({"ticker": bad_ticker, "price": "not-a-number"}, sort_keys=True) + "\n"
    ).encode("utf-8")
    batch = _put_batch(ctx, firehose, stream, [good_record, bad_record])
    assert batch["FailedPutCount"] == 0, (
        f"PutRecordBatch must accept both records regardless of the later conversion verdict: "
        f"{batch!r}"
    )

    sql = f'SELECT ticker, price FROM "{schema["database"]}"."{schema["table"]}"'
    _qid, rows = _poll_rows(
        ctx,
        sql,
        schema["database"],
        workgroup,
        lambda rs: len(rs) >= 1,
        timeout_s=480.0,
        description="Athena returns the coercible row",
    )
    assert rows == [[good_ticker, "2.5"]], (
        f"expected exactly one row, the numeric-string sibling coerced to 2.5, got {rows!r}"
    )
    landed_tickers = {r[0] for r in rows}
    assert bad_ticker not in landed_tickers, (
        f"the non-numeric-string record was converted and stored as a queryable row anyway: "
        f"{rows!r}"
    )

    err_keys = _poll_until(
        lambda: _list_keys(ctx, bucket, "err/"),
        lambda ks: len(ks) > 0,
        timeout_s=300,
        interval_s=10,
        description="the non-numeric-string record lands under the error prefix",
    )
    assert len(err_keys) == 1, f"expected exactly one error object, got {sorted(err_keys)!r}"
    lines = [
        line
        for line in ctx.client("s3")
        .get_object(Bucket=bucket, Key=err_keys[0])["Body"]
        .read()
        .decode("utf-8")
        .splitlines()
        if line.strip()
    ]
    assert len(lines) == 1, f"expected exactly one error line, got {len(lines)}: {lines!r}"
    err_doc = json.loads(lines[0])
    assert err_doc["lastErrorCode"] == "DataFormatConversion.MalformedData", (
        f"a double column fed a non-numeric string must fail with lastErrorCode "
        f"DataFormatConversion.MalformedData, got {err_doc.get('lastErrorCode')!r}: {err_doc!r}"
    )
    assert base64.b64decode(err_doc["rawData"]) == bad_record, (
        f"rawData decoded to {base64.b64decode(err_doc['rawData'])!r}, expected the original "
        f"bytes {bad_record!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
