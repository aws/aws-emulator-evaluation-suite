"""import-then-export-labels-task-run-round-trips-label-file."""
from __future__ import annotations

import csv
import io
import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-then-export-labels-task-run-round-trips-label-file"
GROUP = "server-side"
SERVICES = ["glue", "s3", "iam"]

_LABEL_ROWS = [
    {"id": "1", "name": "sim2real-alpha", "labeling_set_id": "0", "label": "0"},
    {"id": "2", "name": "sim2real-alpha-dup", "labeling_set_id": "0", "label": "0"},
    {"id": "3", "name": "sim2real-bravo", "labeling_set_id": "1", "label": "0"},
    {"id": "4", "name": "sim2real-charlie", "labeling_set_id": "1", "label": "1"},
]


# CreateMLTransform only stores configuration; StartImportLabelsTaskRun and
# StartExportLabelsTaskRun each launch a real Glue task run, which is billed compute.
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """StartImportLabelsTaskRun loads a label file into a FindMatches transform, and
    StartExportLabelsTaskRun writes back out exactly the (id, label) pairs it holds.
    """
    glue = ctx.client("glue")
    bucket, db_name, table_name = _provision_table(ctx)
    role_arn = _provision_role(ctx, bucket)

    transform_id = _create_find_matches_transform(ctx, glue, db_name, table_name, role_arn)

    import_key = "labels/taught.csv"
    _put_label_csv(ctx, bucket, import_key, _LABEL_ROWS)

    import_run_id = glue.start_import_labels_task_run(
        TransformId=transform_id,
        InputS3Path=f"s3://{bucket}/{import_key}",
        ReplaceAllLabels=True,
    )["TaskRunId"]
    imported = _poll_task_run_terminal(glue, transform_id, import_run_id)
    assert imported["Status"] == "SUCCEEDED", f"label import did not succeed: {imported}"

    export_prefix = "exported-labels/"
    export_run_id = glue.start_export_labels_task_run(
        TransformId=transform_id,
        OutputS3Path=f"s3://{bucket}/{export_prefix}",
    )["TaskRunId"]
    assert export_run_id != import_run_id, "import and export produced the same TaskRunId"
    exported = _poll_task_run_terminal(glue, transform_id, export_run_id)
    assert exported["Status"] == "SUCCEEDED", f"label export did not succeed: {exported}"

    pairs = _read_exported_pairs(ctx, bucket, export_prefix)
    expected_pairs = {(row["id"], row["label"]) for row in _LABEL_ROWS}
    assert pairs == expected_pairs, (
        f"expected the exported file to hold the (id, label) pairs it was taught {sorted(expected_pairs)}, "
        f"got {sorted(pairs)}"
    )


def _poll_task_run_terminal(glue, transform_id: str, task_run_id: str, timeout_s: float = 600.0, interval_s: float = 15.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = glue.get_ml_task_run(TransformId=transform_id, TaskRunId=task_run_id)
        if last["Status"] not in ("STARTING", "RUNNING"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"task run {task_run_id!r} did not reach a terminal state within {timeout_s}s (last={last!r})")


def _read_exported_pairs(ctx, bucket: str, prefix: str) -> set[tuple[str, str]]:
    s3 = ctx.client("s3")
    listing = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    keys = [o["Key"] for o in listing.get("Contents", []) if not o["Key"].endswith("/")]
    assert keys, f"expected StartExportLabelsTaskRun to write at least one object under {prefix!r}, found none"

    pairs: set[tuple[str, str]] = set()
    for key in keys:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode()
        for row in csv.DictReader(io.StringIO(body)):
            pairs.add((row["id"], row["label"]))
    return pairs


def _put_label_csv(ctx, bucket: str, key: str, rows: list[dict]) -> None:
    s3 = ctx.client("s3")
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["id", "name", "labeling_set_id", "label"])
    writer.writeheader()
    writer.writerows(rows)
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue().encode())


def _create_find_matches_transform(ctx, glue, db_name: str, table_name: str, role_arn: str) -> str:
    deadline = time.monotonic() + 90.0
    while True:
        try:
            created = glue.create_ml_transform(
                Name=ctx.unique_name("sim2real-glue-mltransform-"),
                InputRecordTables=[{"DatabaseName": db_name, "TableName": table_name}],
                Parameters={
                    "TransformType": "FIND_MATCHES",
                    "FindMatchesParameters": {"PrimaryKeyColumnName": "id"},
                },
                Role=role_arn,
            )
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "InvalidInputException") and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise
    transform_id = created["TransformId"]
    ctx.on_cleanup(lambda: glue.delete_ml_transform(TransformId=transform_id))
    return transform_id


def _provision_table(ctx):
    s3 = ctx.client("s3")
    glue = ctx.client("glue")

    bucket = ctx.unique_name("sim2real-glue-mltx").replace("_", "-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _empty_and_delete_bucket():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objects = page.get("Contents", [])
            if objects:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objects]})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_delete_bucket)

    data_prefix = "records/"
    rows = "\n".join(f"{row['id']},{row['name']}" for row in _LABEL_ROWS)
    s3.put_object(Bucket=bucket, Key=f"{data_prefix}part-0.csv", Body=rows.encode())

    db_name = ctx.unique_name("sim2real_glue_mltx_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    table_name = ctx.unique_name("sim2real_glue_mltx_tbl_").replace("-", "_")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "string"}, {"Name": "name", "Type": "string"}],
                "Location": f"s3://{bucket}/{data_prefix}",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                    "Parameters": {"field.delim": ","},
                },
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=table_name))
    return bucket, db_name, table_name


def _provision_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-mltx-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
        )
    )

    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="mltx-s3-access", PolicyDocument=json.dumps(inline_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="mltx-s3-access"))

    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
