"""list-column-statistics-task-runs-ordering-most-recent-first."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-column-statistics-task-runs-ordering-most-recent-first"
GROUP = "ordering"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListColumnStatisticsTaskRuns (account-wide) orders task runs most-recent-first: of two
    sequential runs against the same table, the later one must appear before the earlier one
    in the returned id list, even though the list may also contain unrelated ids."""
    glue = ctx.client("glue")
    bucket = _create_bucket(ctx)
    _put_csv_data(ctx, bucket, "data/part-0000.csv")
    role = _create_glue_role(ctx)

    db_name = ctx.unique_name("sim2real_glue_db_")
    table_name = ctx.unique_name("sim2real_glue_tbl_")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Location": f"s3://{bucket}/data/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "Columns": [{"Name": "id", "Type": "bigint"}, {"Name": "name", "Type": "string"}],
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                    "Parameters": {"field.delim": ","},
                },
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=table_name))

    def _start():
        return glue.start_column_statistics_task_run(
            DatabaseName=db_name, TableName=table_name, Role=role["arn"]
        )["ColumnStatisticsTaskRunId"]

    # Two runs against the same table cannot overlap (ColumnStatisticsTaskRunningException),
    # so run1 must reach a terminal state before run2 is started.
    run_id_1 = _retry_on_role_propagation(_start, timeout_s=150, interval_s=10)
    _poll_until(
        lambda: glue.get_column_statistics_task_run(ColumnStatisticsTaskRunId=run_id_1)[
            "ColumnStatisticsTaskRun"
        ]["Status"],
        lambda status: status in ("SUCCEEDED", "FAILED", "STOPPED"),
        timeout_s=900,
        interval_s=15,
    )
    run_id_2 = _start()
    ctx.on_cleanup(lambda: _safe_stop(glue, db_name, table_name))

    ids = _list_all_task_run_ids(glue)
    assert run_id_1 in ids, "run 1's id missing from ListColumnStatisticsTaskRuns"
    assert run_id_2 in ids, "run 2's id missing from ListColumnStatisticsTaskRuns"
    assert ids.index(run_id_2) < ids.index(run_id_1), (
        f"expected the more-recently-started run ({run_id_2}) to sort before the older "
        f"one ({run_id_1})"
    )


# ===== helpers =====


def _list_all_task_run_ids(glue, max_pages=25):
    ids: list[str] = []
    token = None
    for _ in range(max_pages):
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        resp = glue.list_column_statistics_task_runs(**kwargs)
        ids.extend(resp.get("ColumnStatisticsTaskRunIds", []))
        token = resp.get("NextToken")
        if not token:
            break
    return ids


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


def _retry_on_role_propagation(fn, *, timeout_s=120.0, interval_s=5.0):
    # A freshly-created role's trust policy is not immediately visible to Glue's own
    # AssumeRole call; real AWS surfaces that lag as either AccessDeniedException or
    # InvalidInputException ("Service is unable to assume provided role").
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in ("AccessDeniedException", "InvalidInputException") or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _safe_stop(glue, db_name, table_name):
    try:
        glue.stop_column_statistics_task_run(DatabaseName=db_name, TableName=table_name)
    except ClientError as exc:
        # A finished, stopping or already-deleted run has nothing left to stop.
        if exc.response["Error"]["Code"] not in (
            "ColumnStatisticsTaskNotRunningException",
            "ColumnStatisticsTaskStoppingException",
            "EntityNotFoundException",
        ):
            raise


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-glue-").lower().replace("_", "-")
    kwargs = {}
    # us-east-1 rejects an explicit LocationConstraint; every other region requires one.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _put_csv_data(ctx, bucket, key):
    s3 = ctx.client("s3")
    body = "\n".join(f"{i},name-{i}" for i in range(1, 51)).encode("utf-8")
    s3.put_object(Bucket=bucket, Key=key, Body=body)


def _create_glue_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    for policy_arn in (
        "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
        "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    ):
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    return {"name": name, "arn": role_arn}


def _delete_role(ctx, name):
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
