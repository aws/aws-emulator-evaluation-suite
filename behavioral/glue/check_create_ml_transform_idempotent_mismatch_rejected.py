"""create-ml-transform-idempotent-mismatch-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-ml-transform-idempotent-mismatch-rejected"
GROUP = "error-semantics"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Reusing an existing MLTransform Name in a second CreateMLTransform call returns
    AlreadyExistsException regardless of whether the Parameters differ (CreateMLTransform has no
    ClientToken-based idempotency); the original transform's parameters are left untouched."""
    glue = ctx.client("glue")
    role_arn = _ensure_glue_role(ctx)
    table = _create_ml_table(ctx)
    name = ctx.unique_name("sim2real-mlxform-")
    input_tables = [{"DatabaseName": table["database"], "TableName": table["table"]}]
    params1 = {"TransformType": "FIND_MATCHES", "FindMatchesParameters": {"PrimaryKeyColumnName": "id"}}

    transform_id = _retry_until_role_usable(
        lambda: glue.create_ml_transform(
            Name=name, InputRecordTables=input_tables, Parameters=params1, Role=role_arn
        )
    )["TransformId"]
    ctx.on_cleanup(lambda: _safe_delete_ml_transform(ctx, transform_id))

    params2 = {"TransformType": "FIND_MATCHES", "FindMatchesParameters": {"PrimaryKeyColumnName": "value"}}
    code, message = _error(
        lambda: glue.create_ml_transform(
            Name=name, InputRecordTables=input_tables, Parameters=params2, Role=role_arn
        )
    )
    assert code == "AlreadyExistsException", code
    assert message == f"Transform with name {name} already exists", f"unexpected CreateMLTransform message: {message!r}"

    # effect absent: the transform's original primary key parameter is untouched
    desc = glue.get_ml_transform(TransformId=transform_id)
    actual_key = desc["Parameters"]["FindMatchesParameters"]["PrimaryKeyColumnName"]
    assert actual_key == "id", f"expected original PrimaryKeyColumnName 'id' untouched, got {actual_key!r}"

    # positive control: a different Name with the same parameters is accepted
    name2 = ctx.unique_name("sim2real-mlxform2-")
    transform_id_2 = glue.create_ml_transform(
        Name=name2, InputRecordTables=input_tables, Parameters=params1, Role=role_arn
    )["TransformId"]
    ctx.on_cleanup(lambda: _safe_delete_ml_transform(ctx, transform_id_2))
    assert transform_id_2 != transform_id, "expected a distinct TransformId for a distinct Name"

    # terminal read: independent of the mutating call, at the destination
    desc2 = glue.get_ml_transform(TransformId=transform_id_2)
    assert desc2["Name"] == name2, f"expected Name {name2!r}, got {desc2.get('Name')!r}"
    key2 = desc2["Parameters"]["FindMatchesParameters"]["PrimaryKeyColumnName"]
    assert key2 == "id", f"expected the positive control's PrimaryKeyColumnName 'id', got {key2!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, because an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _ensure_glue_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
    policy_arns = (
        "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    )
    for policy_arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        for policy_arn in policy_arns:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _retry_until_role_usable(fn, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("AccessDeniedException", "InvalidInputException"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _create_ml_table(ctx):
    s3 = ctx.client("s3")
    glue = ctx.client("glue")
    bucket = ctx.unique_name("sim2real-glue-ml-").lower()
    kwargs = {"Bucket": bucket}
    # us-east-1 literal: S3 CreateBucket API quirk, not a region pin — that region rejects an
    # explicit LocationConstraint pointing at itself. ctx.region still drives the actual bucket region.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup_bucket():
        try:
            resp = s3.list_objects_v2(Bucket=bucket)
            for obj in resp.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup_bucket)
    s3.put_object(Bucket=bucket, Key="data/sample.csv", Body=b"id,value\n1,10\n2,20\n3,30\n")

    db_name = ctx.unique_name("sim2real_glue_ml_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: _safe_delete_database(ctx, db_name))
    table_name = "sample_tbl"
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "string"}, {"Name": "value", "Type": "string"}],
                "Location": f"s3://{bucket}/data/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                    "Parameters": {"field.delim": ","},
                },
            },
        },
    )
    return {"database": db_name, "table": table_name, "bucket": bucket}


def _safe_delete_database(ctx, db_name):
    try:
        ctx.client("glue").delete_database(Name=db_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _safe_delete_ml_transform(ctx, transform_id):
    try:
        ctx.client("glue").delete_ml_transform(TransformId=transform_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
