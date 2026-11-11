"""glue-column-statistics-computed-from-real-data-match-the-known-distribution."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "glue-column-statistics-computed-from-real-data-match-the-known-distribution"
GROUP = 'catalog-statistics'
SERVICES = ['glue', 's3']

# The known distribution. Two rows leave `id` empty, so the null count is checkable, and the
# cardinality is deliberately small so the distinct count is exact rather than sketched.
_ID_VALUES = [3, 3, 8, 12, 12, 25, 41]
_NULL_ROWS = 2
_MIN = min(_ID_VALUES)
_MAX = max(_ID_VALUES)
_DISTINCT = len(set(_ID_VALUES))
_CSV = b"id,tag\n" + b"".join(
    f"{v},t{i}\n".encode() for i, v in enumerate(_ID_VALUES)) + b"".join(
    f",n{i}\n".encode() for i in range(_NULL_ROWS))


@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A column-statistics task scans uploaded S3 data and reports its exact min, max, null count
    and distinct count for a bigint column, typed as long.
    """
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-behav-gluestats-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real",
                                                             "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key="stats/rows.csv", Body=_CSV)

    role_arn = _create_glue_role(ctx, iam, bucket)

    database = ctx.unique_name("sim2real_behav_gluedb_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": database})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_database(Name=database),
                                         f"glue database {database}"))

    table = "measured_rows"
    glue.create_table(DatabaseName=database, TableInput={
        "Name": table,
        "TableType": "EXTERNAL_TABLE",
        "Parameters": {"classification": "csv", "skip.header.line.count": "1"},
        "StorageDescriptor": {
            "Columns": [{"Name": "id", "Type": "bigint"},
                        {"Name": "tag", "Type": "string"}],
            "Location": f"s3://{bucket}/stats/",
            "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
            "OutputFormat":
                "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
            "SerdeInfo": {
                "SerializationLibrary":
                    "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                "Parameters": {"field.delim": ","}}}})
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: glue.delete_table(DatabaseName=database, Name=table),
        f"glue table {database}.{table}"))

    task = _statistics_task_to_terminal(glue, database, table, role_arn, ["id"])
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: glue.delete_column_statistics_for_table(
            DatabaseName=database, TableName=table, ColumnName="id"),
        f"column statistics {database}.{table}.id"))

    assert task["Status"] == "SUCCEEDED", (
        f"the statistics task ended {task['Status']!r}: {task.get('ErrorMessage')!r}"
    )

    response = glue.get_column_statistics_for_table(
        DatabaseName=database, TableName=table, ColumnNames=["id"])
    assert response.get("Errors") in (None, []), (
        f"GetColumnStatisticsForTable reported {response.get('Errors')!r}"
    )
    statistics_list = response["ColumnStatisticsList"]
    assert len(statistics_list) == 1, (
        f"expected statistics for exactly one column, got "
        f"{[s.get('ColumnName') for s in statistics_list]!r}"
    )
    statistics = statistics_list[0]
    assert statistics["ColumnName"] == "id", (
        f"statistics were returned for column {statistics['ColumnName']!r}, not 'id'"
    )
    data = statistics["StatisticsData"]["LongColumnStatisticsData"]

    assert data["MinimumValue"] == _MIN, (
        f"reported minimum {data['MinimumValue']!r}, the uploaded data's minimum is "
        f"{_MIN!r}"
    )
    assert data["MaximumValue"] == _MAX, (
        f"reported maximum {data['MaximumValue']!r}, the uploaded data's maximum is "
        f"{_MAX!r}"
    )
    assert data["NumberOfNulls"] == _NULL_ROWS, (
        f"reported {data['NumberOfNulls']!r} nulls, the check uploaded {_NULL_ROWS!r} rows "
        f"with an empty id"
    )
    # Exact, not a range: at this small cardinality AWS's distinct-count sketch is exact.
    assert data["NumberOfDistinctValues"] == _DISTINCT, (
        f"reported {data['NumberOfDistinctValues']!r} distinct values, the uploaded data "
        f"has {_DISTINCT!r} ({sorted(set(_ID_VALUES))!r})"
    )
    assert statistics["ColumnType"] == "long", (
        f"statistics were computed as {statistics['ColumnType']!r}, expected 'long' for a "
        f"bigint column"
    )


# ===== helpers =====

def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})


def _create_glue_role(ctx, iam, bucket: str) -> str:
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Principal": {"Service": "glue.amazonaws.com"},
                       "Action": "sts:AssumeRole"}]})
    role = ctx.unique_name("sim2real-behav-gluerole-")
    arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: iam.delete_role(RoleName=role),
                                         f"iam role {role}"))
    managed = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role, PolicyArn=managed)
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: iam.detach_role_policy(RoleName=role, PolicyArn=managed),
        f"detach {managed} from {role}"))
    iam.put_role_policy(RoleName=role, PolicyName="sim2real-s3", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"],
                       "Resource": f"arn:aws:s3:::{bucket}/*"},
                      {"Effect": "Allow", "Action": ["s3:ListBucket"],
                       "Resource": f"arn:aws:s3:::{bucket}"}]}))
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: iam.delete_role_policy(RoleName=role, PolicyName="sim2real-s3"),
        f"inline policy on {role}"))
    return arn


def _retry_delete(fn: Callable[[], Any], label: str, *, timeout_s: float = 120.0) -> None:
    """Delete with a bounded retry, because ctx.on_cleanup SWALLOWS teardown exceptions:
    a throttled or dependency-blocked delete would leak silently while the check passes."""
    from botocore.exceptions import ClientError

    gone = ("EntityNotFoundException", "NoSuchEntity", "NoSuchBucket",
            "ResourceNotFoundException", "404")
    transient = ("ThrottlingException", "Throttling", "TooManyRequestsException",
                 "OperationTimeoutException", "ConcurrentModificationException",
                 "DeleteConflict", "CrawlerRunningException", "RequestLimitExceeded")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in gone:
                return
            if code not in transient or time.monotonic() >= deadline:
                raise RuntimeError(f"{label}: {code}: {err}") from err
            time.sleep(3)
        except Exception as exc:  # noqa: BLE001 - re-raised
            raise RuntimeError(f"{label}: {type(exc).__name__}: {exc}") from exc


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    from botocore.exceptions import ClientError

    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                       for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objects:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise
        return
    _retry_delete(lambda: s3.delete_bucket(Bucket=bucket), f"s3 bucket {bucket}")


def _statistics_task_to_terminal(glue, database: str, table: str, role_arn: str,
                                 columns: list, *, timeout_s: float = 600.0) -> dict:
    """Start the task and poll GetColumnStatisticsTaskRun to a terminal Status.

    StartColumnStatisticsTaskRun also validates the role synchronously, so it is retried on
    InvalidInputException while IAM propagation is in flight.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    run_id = None
    while run_id is None:
        try:
            run_id = glue.start_column_statistics_task_run(
                DatabaseName=database, TableName=table, Role=role_arn,
                ColumnNameList=columns)["ColumnStatisticsTaskRunId"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidInputException" \
                    or time.monotonic() >= deadline:
                raise
            time.sleep(5)
    status = None
    record: dict = {}
    while time.monotonic() < deadline:
        record = glue.get_column_statistics_task_run(
            ColumnStatisticsTaskRunId=run_id)["ColumnStatisticsTaskRun"]
        status = record.get("Status")
        if status in ("SUCCEEDED", "FAILED", "STOPPED"):
            return record
        time.sleep(2)
    raise AssertionError(
        f"column statistics task {run_id!r} did not reach a terminal status within "
        f"{timeout_s}s (last status {status!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
