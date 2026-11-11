"""firehose-interval-ceiling-900-echoed-and-size-hint-flushes-through-athena."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firehose-interval-ceiling-900-echoed-and-size-hint-flushes-through-athena"

GROUP = "ingest"

SERVICES = ["athena", "firehose", "glue", "s3"]


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
        # us-east-1 is the one region where S3 CreateBucket rejects a LocationConstraint.
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
    ctx.on_cleanup(lambda: glue.delete_database(Name=db))
    table = _glue_name(ctx, "tbl")
    glue.create_table(
        DatabaseName=db,
        TableInput={
            "Name": table,
            "TableType": "EXTERNAL_TABLE",
            "Parameters": {"classification": "json", "EXTERNAL": "TRUE"},
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "int"}],
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
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db, Name=table))
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
        lambda: ctx.client("athena").delete_work_group(WorkGroup=name, RecursiveDeleteOption=True)
    )
    return name


def _dest(role_arn, bucket_arn, prefix, interval_s, size_mb):
    return {
        "RoleARN": role_arn,
        "BucketARN": bucket_arn,
        "Prefix": prefix,
        "BufferingHints": {"SizeInMBs": size_mb, "IntervalInSeconds": interval_s},
        "CompressionFormat": "UNCOMPRESSED",
    }


def _create_with_role_retry(ctx, firehose, *, name, role_arn, bucket_arn, prefix, interval_s, size_mb, deadline):
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=_dest(role_arn, bucket_arn, prefix, interval_s, size_mb),
            )
            return
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


def _delete_stream(firehose, name: str, *, timeout_s: float = 600.0) -> None:
    """Teardown: DeleteDeliveryStream refuses a stream still CREATING (ResourceInUseException) and
    deletes asynchronously, so retry the delete, then poll until the stream is not found."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(3.0)
    while True:
        try:
            status = firehose.describe_delivery_stream(DeliveryStreamName=name)[
                "DeliveryStreamDescription"]["DeliveryStreamStatus"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise TimeoutError(f"stream {name} still {status!r} {timeout_s:.0f}s after DeleteDeliveryStream")
        time.sleep(3.0)


def _put_batch_with_retry(firehose, stream, records, *, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            out = firehose.put_record_batch(
                DeliveryStreamName=stream, Records=[{"Data": r} for r in records]
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("AccessDeniedException", "AccessDenied") and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
        assert out["FailedPutCount"] == 0, f"PutRecordBatch refused records: {out['RequestResponses'][:3]!r}"
        return out


def _run_query(athena, sql, database, workgroup, *, timeout_s=180.0):
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


def _get_rows(athena, qid) -> list[list[str | None]]:
    rows: list[list[str | None]] = []
    for page in athena.get_paginator("get_query_results").paginate(QueryExecutionId=qid):
        for row in page["ResultSet"]["Rows"]:
            rows.append([d.get("VarCharValue") for d in row["Data"]])
    return rows


def _list_keys(s3, bucket, prefix) -> list[str]:
    return [
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix)
        for o in page.get("Contents", [])
    ]


#: Records per PutRecordBatch call and calls: about 1 MB per call, 5 MB in all.
_BATCH = 125
_BATCHES = 5
#: A bound to fail at, below the 900 s interval, so only the size hint can satisfy it.
_SIZE_FLUSH_DEADLINE_S = 300.0


def _capped(ctx, budget_s):
    left = ctx.time_left()
    return budget_s if left is None else max(1.0, min(budget_s, left))


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """CreateDeliveryStream refuses `IntervalInSeconds` 901 and accepts the 900 s ceiling, which
    DescribeDeliveryStream echoes; with that interval the 1 MB size hint alone flushes the
    buffer, and every delivered line is visible through a Glue table queried by Athena.

    Reference: https://docs.aws.amazon.com/firehose/latest/dev/create-configure-backup.html
    """
    bucket = _new_bucket(ctx)
    bucket_arn = f"arn:aws:s3:::{bucket}"
    role = _firehose_role(ctx, bucket_arn=bucket_arn)
    firehose = ctx.client("firehose")
    s3 = ctx.client("s3")
    workgroup = _create_workgroup(ctx, f"s3://{bucket}/athena-results/")

    bad_name = _xname(ctx, "dstream-bad")
    bad_prefix = f"{bad_name}/"
    deadline = time.monotonic() + 180
    # Removes the stream should CreateDeliveryStream wrongly accept the interval.
    ctx.on_cleanup(lambda: _delete_stream(firehose, bad_name))
    try:
        _create_with_role_retry(
            ctx, firehose, name=bad_name, role_arn=role["arn"], bucket_arn=bucket_arn,
            prefix=bad_prefix, interval_s=901, size_mb=5, deadline=deadline,
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        expected = (
            "1 validation error detected: Value at "
            "'extendedS3DestinationConfiguration.bufferingHints.intervalInSeconds' failed to "
            "satisfy constraint: Member must have value less than or equal to 900"
        )
        assert (code, message) == ("ValidationException", expected), (
            f"IntervalInSeconds=901 is above AWS's documented 900s ceiling; expected "
            f"('ValidationException', {expected!r}), got {(code, message)!r}"
        )
    else:
        raise AssertionError(
            f"CreateDeliveryStream accepted IntervalInSeconds=901 for {bad_name!r}, above the "
            f"documented 900s ceiling"
        )

    try:
        firehose.describe_delivery_stream(DeliveryStreamName=bad_name)
    except ClientError as exc:
        not_found_code = exc.response.get("Error", {}).get("Code")
        not_found_message = exc.response.get("Error", {}).get("Message")
        expected = f"Firehose under account {ctx.account} not found."
        assert (not_found_code, not_found_message) == ("ResourceNotFoundException", expected), (
            f"the rejected stream {bad_name!r} must not exist; expected "
            f"('ResourceNotFoundException', {expected!r}), got {(not_found_code, not_found_message)!r}"
        )
    else:
        raise AssertionError(
            f"CreateDeliveryStream rejected IntervalInSeconds=901 but {bad_name!r} exists anyway "
            f"— the input was rejected without preventing the create"
        )

    good_name = _xname(ctx, "dstream-good")
    good_prefix = f"{good_name}/"
    schema = _create_glue_table(ctx, f"s3://{bucket}/{good_prefix}")
    deadline = time.monotonic() + 180
    _create_with_role_retry(
        ctx, firehose, name=good_name, role_arn=role["arn"], bucket_arn=bucket_arn,
        prefix=good_prefix, interval_s=900, size_mb=1, deadline=deadline,
    )
    ctx.on_cleanup(lambda: _delete_stream(firehose, good_name))
    status = _poll_until(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=good_name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"],
        lambda s: s in ("ACTIVE", "CREATING_FAILED"),
        timeout_s=300,
        interval_s=5,
        description=f"stream {good_name} reaches ACTIVE",
    )
    assert status == "ACTIVE", (
        f"IntervalInSeconds=900 (the documented ceiling, inclusive) must be accepted; got "
        f"{status!r}, proving the rejection above is about the value and not the role or bucket"
    )
    dest = firehose.describe_delivery_stream(DeliveryStreamName=good_name)[
        "DeliveryStreamDescription"
    ]["Destinations"][0]["ExtendedS3DestinationDescription"]
    assert dest["BufferingHints"] == {"SizeInMBs": 1, "IntervalInSeconds": 900}, (
        f"DescribeDeliveryStream must echo the configured hints, got {dest['BufferingHints']!r}"
    )

    # The first buffer condition met triggers delivery: about 5 MB of records crosses the 1 MB
    # size hint many times over, long before the 900 s interval.
    pad = "x" * 8000
    sent_ids = set()
    for batch in range(_BATCHES):
        ids = range(batch * _BATCH, (batch + 1) * _BATCH)
        sent_ids.update(ids)
        _put_batch_with_retry(
            firehose, good_name,
            [(json.dumps({"id": i, "pad": pad}) + "\n").encode("utf-8") for i in ids],
        )
    keys = _poll_until(
        lambda: _list_keys(s3, bucket, good_prefix),
        lambda ks: len(ks) > 0,
        timeout_s=_capped(ctx, _SIZE_FLUSH_DEADLINE_S),
        interval_s=3.0,
        description=f"a size-triggered object delivered under {good_prefix!r}",
    )
    lines_per_key = {}
    for key in keys:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8")
        ids = [json.loads(line)["id"] for line in body.splitlines() if line.strip()]
        assert ids and set(ids) <= sent_ids, (
            f"object {key!r} holds ids outside the {len(sent_ids)} sent: {sorted(set(ids) - sent_ids)[:5]!r}"
        )
        lines_per_key[f"s3://{bucket}/{key}"] = len(ids)

    athena = ctx.client("athena")
    sql = (
        f'SELECT "$path", count(*) FROM "{schema["database"]}"."{schema["table"]}" GROUP BY 1'
    )
    qid, state, reason = _run_query(athena, sql, schema["database"], workgroup)
    assert state == "SUCCEEDED", f"Athena query {qid} ended {state!r}: {reason!r}"
    rows = _get_rows(athena, qid)
    seen = {path: int(n) for path, n in rows[1:]}
    # Objects delivered after the listing may show up in Athena too; every listed one must match.
    got = {path: seen.get(path) for path in lines_per_key}
    assert got == lines_per_key, (
        f"Athena must count every line Firehose delivered in each listed object; S3 holds "
        f"{lines_per_key!r}, Athena counted {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
