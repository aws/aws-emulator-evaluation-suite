"""fhtransform-processing-failed-is-attributed-to-the-transform-not-the-parquet-conversion."""

from __future__ import annotations

import base64
import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fhtransform-processing-failed-is-attributed-to-the-transform-not-the-parquet-conversion"

GROUP = "transformation"

SERVICES = ["athena", "firehose", "glue", "lambda", "s3"]


_COLUMNS = [
    {"Name": "marker", "Type": "string"},
    {"Name": "n", "Type": "int"},
    {"Name": "kind", "Type": "string"},
    {"Name": "fn", "Type": "string"},
]


_TRANSFORM = """
    import base64
    import json


    def lambda_handler(event, context):
        out = []
        for rec in event["records"]:
            src = json.loads(base64.b64decode(rec["data"]).decode("utf-8"))
            if src["kind"] == "fail":
                # The ONE broken thing: this verdict. The record itself is valid JSON that the
                # Glue schema could convert perfectly well.
                out.append({"recordId": rec["recordId"], "result": "ProcessingFailed"})
                continue
            rewritten = {
                "marker": src["marker"],
                "n": src["n"],
                "kind": src["kind"].upper(),
                "fn": context.function_name,
            }
            body = (json.dumps(rewritten, sort_keys=True) + "\\n").encode("utf-8")
            out.append(
                {
                    "recordId": rec["recordId"],
                    "result": "Ok",
                    "data": base64.b64encode(body).decode("utf-8"),
                }
            )
        return {"records": out}
"""


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c2",
    "cap:c3", "timing:real-time",
)
def run(ctx) -> None:
    """With a Lambda transform and Parquet conversion, a record the transform returns
    `ProcessingFailed` for lands under `processing-failed` (not `format-conversion-failed`) with its
    original bytes and becomes no Athena row, while its siblings in the same batch are queryable.
    """
    bucket = _new_bucket(ctx)
    bucket_arn = f"arn:aws:s3:::{bucket}"
    data_location = f"s3://{bucket}/main/"
    schema = _create_glue_table(ctx, _COLUMNS, data_location)
    workgroup = _create_workgroup(ctx, f"s3://{bucket}/athena-results/")
    fn = _create_transform_lambda(ctx, _TRANSFORM)
    role = _firehose_role(
        ctx,
        bucket_arn=bucket_arn,
        extra_statements=[
            {
                "Effect": "Allow",
                "Action": ["lambda:InvokeFunction", "lambda:GetFunctionConfiguration"],
                "Resource": [fn["arn"], f"{fn['arn']}:*"],
            },
            {"Effect": "Allow", "Action": _GLUE_READ_ACTIONS, "Resource": "*"},
        ],
    )
    firehose, stream = _create_stream(
        ctx,
        role_arn=role["arn"],
        bucket_arn=bucket_arn,
        prefix="main/",
        error_prefix="err/!{firehose:error-output-type}/",
        extra=dict(
            _conversion_config(role_arn=role["arn"], schema=schema, region=ctx.region),
            ProcessingConfiguration={
                "Enabled": True,
                "Processors": [_lambda_processor(fn["arn"])],
            },
        ),
    )

    ok_markers = [ctx.unique_name("fhok-") for _ in range(2)]
    bad_marker = ctx.unique_name("fhbad-")
    # The failed record has its siblings' shape, so only the transform's verdict rejects it.
    plan = [(ok_markers[0], 1, "good"), (bad_marker, 2, "fail"), (ok_markers[1], 3, "good")]
    records = [
        (json.dumps({"marker": m, "n": n, "kind": k}, sort_keys=True) + "\n").encode("utf-8")
        for m, n, k in plan
    ]
    bad_record = records[1]
    batch = _put_batch_with_retry(ctx, firehose, stream, records)
    assert batch["FailedPutCount"] == 0, (
        f"PutRecordBatch must accept all three records regardless of the later transform verdict: "
        f"{batch!r}"
    )

    sql = (
        f'SELECT marker, n, kind, fn FROM "{schema["database"]}"."{schema["table"]}" ORDER BY n'
    )
    # The Ok siblings arriving is the barrier that makes the failed record's absence real.
    _qid, rows = _poll_rows(
        ctx,
        sql,
        schema["database"],
        workgroup,
        lambda rs: len(rs) >= len(ok_markers),
        timeout_s=480.0,
        description="Athena returns the two successfully transformed rows",
    )
    expected = [[ok_markers[0], "1", "GOOD", fn["name"]], [ok_markers[1], "3", "GOOD", fn["name"]]]
    assert rows == expected, (
        f"Athena returned {rows!r}, expected exactly the two Ok records as transformed "
        f"({expected!r}) and no row for the ProcessingFailed one"
    )
    landed = {c for row in rows for c in row if c is not None}
    assert bad_marker not in landed, (
        f"the ProcessingFailed record was converted and stored as a queryable row anyway: {rows!r}"
    )

    s3 = ctx.client("s3")
    err_keys = _poll_until(
        lambda: _list_keys(ctx, bucket, "err/"),
        lambda ks: len(ks) > 0,
        timeout_s=480.0,
        interval_s=10,
        description="the ProcessingFailed record lands under the error prefix",
    )
    assert len(err_keys) == 1, f"expected one error object, got {sorted(err_keys)!r}"
    err_key = err_keys[0]
    assert err_key.startswith("err/processing-failed/"), (
        f"the error object landed at {err_key!r}; with conversion enabled the failure must still "
        f"be attributed to the processing stage, so the key must carry the processing-failed "
        f"error-output-type and not format-conversion-failed"
    )
    err_doc = json.loads(s3.get_object(Bucket=bucket, Key=err_key)["Body"].read())
    # AWS writes Lambda.ProcessingFailedStatus here and spells the attribution field lambdaARN.
    assert err_doc["errorCode"] == "Lambda.ProcessingFailedStatus", (
        f"the error object reported {err_doc.get('errorCode')!r}: {err_doc!r}"
    )
    assert err_doc.get("errorMessage") == _PROCESSING_FAILED_MESSAGE, (
        f"the error object said {err_doc.get('errorMessage')!r}, expected "
        f"{_PROCESSING_FAILED_MESSAGE!r}: {err_doc!r}"
    )
    assert base64.b64decode(err_doc["rawData"]) == bad_record, (
        f"rawData decoded to {base64.b64decode(err_doc['rawData'])!r}, expected the ORIGINAL "
        f"pre-transform record {bad_record!r} — a diverted record must be recoverable as sent"
    )
    assert err_doc["lambdaARN"].startswith(fn["arn"]), (
        f"the error object attributes the failure to {err_doc.get('lambdaARN')!r}, expected "
        f"{fn['arn']!r}"
    )
    assert "dataCatalogTable" not in err_doc, (
        f"the error object blames the Glue conversion stage for a transform failure: {err_doc!r}"
    )


_PROCESSING_FAILED_MESSAGE = "ProcessingFailed status set for record"

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

_GLUE_READ_ACTIONS = [
    "glue:GetDatabase",
    "glue:GetDatabases",
    "glue:GetTable",
    "glue:GetTables",
    "glue:GetTableVersion",
    "glue:GetTableVersions",
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


def _retry_teardown(fn, *, deadline_s=30.0, interval_s=2.0) -> None:
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
    """Create a DirectPut -> ExtendedS3 delivery stream and poll it to ACTIVE. Firehose assumes the
    delivery role during CreateDeliveryStream, so a fresh role can fail with
    `InvalidArgumentException: ... unable to assume role`; that window is retried to a deadline."""
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
    deadline = time.monotonic() + 180
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


def _conversion_config(*, role_arn: str, schema: dict[str, str], region: str) -> dict[str, Any]:
    """Parquet format conversion driven by a Glue table, with the buffering the feature demands.
    Data format conversion refuses BufferingHints.SizeInMBs below 64, so the 60 s interval is what
    triggers the flush for a handful of small records."""
    return {
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
                "Region": region,
                "VersionId": "LATEST",
            },
        },
    }


def _put_batch_with_retry(ctx, firehose, stream, records, *, timeout_s=180.0):
    """PutRecordBatch, retrying only the delivery-role propagation window at first use: a brand-new
    stream can reject the first put while the role it assumed is still converging."""
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
    """Every key under prefix, paginated; page one is not the whole answer."""
    s3 = ctx.client("s3")
    keys: list[str] = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


def _wait_function_active(ctx, name: str, timeout_s: float = 120.0) -> None:
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda r: r.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"Lambda {name} reaches Active",
    )


def _create_transform_lambda(ctx, handler_code: str) -> dict[str, str]:
    """Create a tagged Firehose transform Lambda (logs-only role, in-memory zip) and wait until
    Active. The function and the log group Lambda creates on first invoke both get a teardown."""
    role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                    ],
                    "Resource": "arn:aws:logs:*:*:*",
                }
            ],
        },
        "role-lambda",
    )
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(handler_code))
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role["arn"],
        Handler="lambda_function.lambda_handler",
        Code={"ZipFile": buf.getvalue()},
        Timeout=60,
        MemorySize=256,
        Tags=dict(_xsvc_resource_tags()),
    )
    deadline = time.monotonic() + 120
    while True:
        try:
            resp = lam.create_function(**kwargs)
            break
        except ClientError as exc:
            # A role created seconds ago cannot yet be assumed by Lambda; bounded retry, not sleep.
            if "cannot be assumed" in str(exc) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(
        lambda: _retry_teardown(lambda: ctx.client("lambda").delete_function(FunctionName=name))
    )
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))
    _wait_function_active(ctx, name)
    return {"name": name, "arn": resp["FunctionArn"]}


def _reap_log_group(ctx, group: str, *, rounds: int = 4, interval_s: float = 4.0) -> None:
    """delete_log_group is one ROUND, not a teardown: a stream buffered by an invoke that already
    returned can flush after the delete and RECREATE the group. Re-delete, then poll for
    reappearance over a bounded window and raise rather than hang if it never converges."""
    logs = ctx.client("logs")
    for _ in range(rounds):
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(interval_s)
        try:
            found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
        except ClientError:
            return
        if not any(g["logGroupName"] == group for g in found):
            return
    raise RuntimeError(f"log group {group} kept reappearing after {rounds} delete rounds")


def _lambda_processor(fn_arn: str) -> dict[str, Any]:
    """The ProcessingConfiguration processor entry that wires a transform Lambda into delivery."""
    return {
        "Type": "Lambda",
        "Parameters": [
            {"ParameterName": "LambdaArn", "ParameterValue": fn_arn},
            {"ParameterName": "NumberOfRetries", "ParameterValue": "1"},
            {"ParameterName": "BufferSizeInMBs", "ParameterValue": "1"},
            {"ParameterName": "BufferIntervalInSeconds", "ParameterValue": "60"},
        ],
    }


def _glue_name(ctx, kind: str) -> str:
    """A Glue-legal name: the catalog rejects '-', so the sim2real prefix is underscore-spelled."""
    return _xname(ctx, kind).replace("-", "_")


def _create_glue_table(ctx, columns: list[dict[str, str]], location: str) -> dict[str, str]:
    """Create a Glue database + Parquet table at `location`; register both teardowns. Firehose
    builds its Parquet writer from this table and Athena reads the same rows through it."""
    glue = ctx.client("glue")
    db = _glue_name(ctx, "db")
    glue.create_database(
        DatabaseInput={"Name": db, "Description": "sim2real-xsvc firehose transform parquet"}
    )
    ctx.on_cleanup(lambda: _retry_teardown(lambda: ctx.client("glue").delete_database(Name=db)))
    table = _glue_name(ctx, "tbl")
    glue.create_table(
        DatabaseName=db,
        TableInput={
            "Name": table,
            "Description": "sim2real-xsvc firehose transform target schema",
            "TableType": "EXTERNAL_TABLE",
            "Parameters": {
                "classification": "parquet",
                "EXTERNAL": "TRUE",
                "sim2real:managed": "true",
            },
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
    ctx.on_cleanup(
        lambda: _retry_teardown(
            lambda: ctx.client("glue").delete_table(DatabaseName=db, Name=table)
        )
    )
    return {"database": db, "table": table}


def _create_workgroup(ctx, output_location: str) -> str:
    """Our own Athena workgroup, so the check never depends on the account's default one."""
    athena = ctx.client("athena")
    name = _xname(ctx, "wg")
    athena.create_work_group(
        Name=name,
        Configuration={
            "ResultConfiguration": {"OutputLocation": output_location},
            "PublishCloudWatchMetricsEnabled": False,
        },
        Description="sim2real-xsvc firehose transform reader",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(
        lambda: _retry_teardown(
            lambda: ctx.client("athena").delete_work_group(
                WorkGroup=name, RecursiveDeleteOption=True
            )
        )
    )
    return name


def _run_query(ctx, sql: str, database: str, workgroup: str, *, timeout_s=300.0):
    """Start one Athena query and poll it to a terminal state; return (id, state, reason)."""
    athena = ctx.client("athena")
    qid = athena.start_query_execution(
        QueryString=sql,
        QueryExecutionContext={"Database": database},
        WorkGroup=workgroup,
    )["QueryExecutionId"]
    state = _poll_until(
        lambda: athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"],
        lambda s: s["State"] in ("SUCCEEDED", "FAILED", "CANCELLED"),
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"Athena query {qid} reaches a terminal state",
    )
    return qid, state["State"], state.get("StateChangeReason")


def _select_rows(ctx, qid: str) -> list[list[str | None]]:
    """Every data row of a SELECT, paginated; row 0 of page 1 is the column header, not data."""
    athena = ctx.client("athena")
    rows: list[list[str | None]] = []
    for page in athena.get_paginator("get_query_results").paginate(QueryExecutionId=qid):
        for row in page["ResultSet"]["Rows"]:
            rows.append([d.get("VarCharValue") for d in row["Data"]])
    return rows[1:]


def _result_columns(ctx, qid: str) -> list[str]:
    """The column names Athena projected, straight from ResultSetMetadata."""
    meta = ctx.client("athena").get_query_results(QueryExecutionId=qid, MaxResults=1)
    return [c["Name"] for c in meta["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]]


def _query_rows(ctx, sql: str, database: str, workgroup: str) -> tuple[str, list[list]]:
    """Run one SELECT and return (query id, data rows), failing loudly on a non-SUCCEEDED state."""
    qid, state, reason = _run_query(ctx, sql, database, workgroup)
    assert state == "SUCCEEDED", f"Athena query {qid} ended {state!r}: {reason!r} for sql {sql!r}"
    return qid, _select_rows(ctx, qid)


def _poll_rows(ctx, sql, database, workgroup, predicate, *, timeout_s=480.0, description="rows"):
    """Re-run a SELECT until its rows satisfy predicate. Athena has no notification to wait on and
    the object it reads is written by an asynchronous delivery agent, so the query IS the probe —
    this polls for the value arriving and never asserts how fast it did."""
    holder: dict[str, Any] = {}

    def probe():
        qid, rows = _query_rows(ctx, sql, database, workgroup)
        holder["qid"] = qid
        return rows

    rows = _poll_until(
        probe, predicate, timeout_s=timeout_s, interval_s=15.0, description=description
    )
    return holder["qid"], rows


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
