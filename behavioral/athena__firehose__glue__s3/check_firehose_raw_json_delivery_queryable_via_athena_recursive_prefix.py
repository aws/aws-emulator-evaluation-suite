"""firehose-raw-json-delivery-queryable-via-athena-recursive-prefix."""

from __future__ import annotations

import json
import re
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firehose-raw-json-delivery-queryable-via-athena-recursive-prefix"

GROUP = "ingest"

SERVICES = ["athena", "firehose", "glue", "s3"]

_DATE_NESTED = re.compile(r"^[^/]+/\d{4}/\d{2}/\d{2}/\d{2}/")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
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
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(policy))
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _glue_name(ctx, kind: str) -> str:
    return _xname(ctx, kind).replace("-", "_")


def _create_glue_table(ctx, location: str) -> dict[str, str]:
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
            "Parameters": {"classification": "json", "EXTERNAL": "TRUE"},
            "StorageDescriptor": {
                "Columns": [
                    {"Name": "id", "Type": "int"},
                    {"Name": "amount", "Type": "double"},
                ],
                "Location": location,
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.openx.data.jsonserde.JsonSerDe",
                    "Parameters": {"serialization.format": "1"},
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


def _create_stream(ctx, *, name, role_arn, bucket_arn, prefix):
    firehose = ctx.client("firehose")
    dest = {
        "RoleARN": role_arn,
        "BucketARN": bucket_arn,
        "Prefix": prefix,
        "ErrorOutputPrefix": "err/!{firehose:error-output-type}/",
        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
        "CompressionFormat": "UNCOMPRESSED",
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
    return firehose


def _put_with_retry(ctx, firehose, stream, data, *, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return firehose.put_record(DeliveryStreamName=stream, Record={"Data": data})
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


def _run_query(ctx, sql, database, workgroup, *, timeout_s=180.0):
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


def _get_rows(ctx, qid) -> list[list[str | None]]:
    athena = ctx.client("athena")
    rows: list[list[str | None]] = []
    for page in athena.get_paginator("get_query_results").paginate(QueryExecutionId=qid):
        for row in page["ResultSet"]["Rows"]:
            rows.append([d.get("VarCharValue") for d in row["Data"]])
    return rows


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/APIReference/API_BufferingHints.html
@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A Firehose stream without format conversion delivers raw JSON under a static Prefix plus its
    own `yyyy/MM/dd/HH/` segments; a non-partitioned Glue table at the static prefix still reads
    every nested object, so Athena's SUM reflects every delivered record.
    """
    bucket = _new_bucket(ctx)
    bucket_arn = f"arn:aws:s3:::{bucket}"
    stream_name = _xname(ctx, "dstream")
    prefix = f"{stream_name}/"
    data_location = f"s3://{bucket}/{prefix}"
    schema = _create_glue_table(ctx, data_location)
    workgroup = _create_workgroup(ctx, f"s3://{bucket}/athena-results/")
    role = _firehose_role(ctx, bucket_arn=bucket_arn)
    firehose = _create_stream(ctx, name=stream_name, role_arn=role["arn"], bucket_arn=bucket_arn, prefix=prefix)

    rows_in = [(1, 10.0), (2, 20.0), (3, 30.0), (4, 40.0), (5, 50.0)]
    for rid, amount in rows_in:
        line = json.dumps({"id": rid, "amount": amount}, sort_keys=True) + "\n"
        _put_with_retry(ctx, firehose, stream_name, line.encode("utf-8"))

    s3 = ctx.client("s3")

    def _nested_keys():
        keys = []
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
            keys.extend(o["Key"] for o in page.get("Contents", []))
        return keys

    delivered = _poll_until(
        _nested_keys,
        lambda ks: len(ks) > 0,
        timeout_s=420.0,
        interval_s=10.0,
        description=f"at least one object delivered under {prefix!r}",
    )
    assert delivered, f"no objects were delivered under prefix {prefix!r}"
    assert all(_DATE_NESTED.match(k) for k in delivered), (
        f"Firehose must append its own yyyy/MM/dd/HH/ segments beneath the static prefix "
        f"{prefix!r}; got keys {delivered!r}"
    )

    sql = f'SELECT sum(amount), count(*) FROM "{schema["database"]}"."{schema["table"]}"'
    qid, state, reason = _run_query(ctx, sql, schema["database"], workgroup)
    assert state == "SUCCEEDED", f"Athena query {qid} ended {state!r}: {reason!r}"
    rows = _get_rows(ctx, qid)
    assert len(rows) == 2, f"expected a header row plus one data row, got {rows!r}"
    header, data = rows
    assert data[0] == "150.0", (
        f"sum(amount) over the delivered rows must reflect every record Firehose nested beneath "
        f"{prefix!r}, not just ones directly under it; got {data!r} (header {header!r})"
    )
    assert data[1] == str(len(rows_in)), (
        f"count(*) must equal the number of records put, got {data!r}"
    )

    err_keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix="err/"):
        err_keys.extend(o["Key"] for o in page.get("Contents", []))
    assert err_keys == [], f"no record in this check should be diverted to the error prefix: {err_keys!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
