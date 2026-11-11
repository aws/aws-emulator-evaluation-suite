"""athena-glue-catalog-missing-permission-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "athena-glue-catalog-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["athena", "glue", "s3"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A query fails when the calling identity lacks glue:GetTable on the catalog table, while
    the same query still succeeds for a caller with full permissions (positive control)."""
    bucket = _create_bucket(ctx)
    db = _sql_name(ctx, "sim2real_ga_perm_db_")
    table = _sql_name(ctx, "perm_tbl_")
    _create_glue_database(ctx, db)
    location = f"s3://{bucket}/data/{table}/"
    _put_text(ctx, bucket, f"data/{table}/part.csv", "1,secret\n")
    columns = [{"Name": "id", "Type": "bigint"}, {"Name": "val", "Type": "string"}]
    _create_csv_table(ctx, db, table, location, columns)
    output = f"s3://{bucket}/athena-results/"

    limited_athena, limited_arn = _create_limited_role_athena_client(ctx, bucket)

    # Negative: the caller has Athena + S3 permissions but no Glue permissions at all.
    qid_bad, state_bad, reason_bad = _run_query(
        limited_athena, f"SELECT * FROM {db}.{table}", db, output
    )
    assert state_bad == "FAILED", f"expected FAILED, got {state_bad} (reason={reason_bad})"
    assert reason_bad is not None, "a FAILED query must report a StateChangeReason"
    # Athena reports the Glue denial verbatim: the assumed-role session, the account's catalog
    # (the first Glue action a query needs), and a message that ends in a space.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    expected_reason = (
        f"Insufficient permissions to execute the query. User: {limited_arn} is not authorized "
        f"to perform: glue:GetDatabase on resource: arn:aws:glue:{ctx.region}:{account_id}:catalog "
        "because no identity-based policy allows the glue:GetDatabase action "
    )
    assert reason_bad == expected_reason, reason_bad

    # The effect is absent: no result set was ever produced for the denied query.
    code, message = _error_code(lambda: limited_athena.get_query_results(QueryExecutionId=qid_bad))
    assert code == "InvalidRequestException", code
    assert message == "Query did not finish successfully. Final query state: FAILED", message

    # Positive control: the default (fully permissioned) caller can run the identical query.
    athena = ctx.client("athena")
    qid_ok, state_ok, reason_ok = _run_query(athena, f"SELECT * FROM {db}.{table}", db, output)
    assert state_ok == "SUCCEEDED", f"control query failed: state={state_ok} reason={reason_ok}"
    rows_ok = _select_rows(athena, qid_ok)
    assert rows_ok == [["1", "secret"]], f"expected the one row the check wrote, got {rows_ok!r}"


def _sql_name(ctx: Any, prefix: str) -> str:
    return ctx.unique_name(prefix).replace("-", "_").lower()


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-ga-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _empty_and_delete_bucket(ctx: Any, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            )
    s3.delete_bucket(Bucket=bucket)


def _put_text(ctx: Any, bucket: str, key: str, content: str) -> None:
    ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=content.encode("utf-8"))


def _create_glue_database(ctx: Any, name: str) -> str:
    glue = ctx.client("glue")
    glue.create_database(DatabaseInput={"Name": name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=name))
    return name


def _csv_storage_descriptor(location: str, columns: list) -> dict:
    return {
        "Columns": columns,
        "Location": location,
        "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
        "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
        "SerdeInfo": {
            "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
            "Parameters": {"field.delim": ","},
        },
    }


def _create_csv_table(ctx: Any, db: str, table: str, location: str, columns: list) -> str:
    glue = ctx.client("glue")
    table_input = {
        "Name": table,
        "TableType": "EXTERNAL_TABLE",
        "StorageDescriptor": _csv_storage_descriptor(location, columns),
        "Parameters": {"EXTERNAL": "TRUE"},
    }
    glue.create_table(DatabaseName=db, TableInput=table_input)
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db, Name=table))
    return table


def _create_limited_role_athena_client(ctx: Any, bucket: str):
    """Create an IAM role with Athena + S3 (but no Glue) permissions, assume it, and return
    an Athena client signed with the assumed-role credentials and the session's ARN."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-ga-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "athena-s3-only"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "athena:StartQueryExecution",
                    "athena:GetQueryExecution",
                    "athena:GetQueryResults",
                    "athena:StopQueryExecution",
                ],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetBucketLocation", "s3:ListBucket"],
                "Resource": f"arn:aws:s3:::{bucket}",
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": f"arn:aws:s3:::{bucket}/*",
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    assumed = _assume_role_with_retry(sts, role_arn, ctx.unique_name("sess-"))
    creds = assumed["Credentials"]
    client = ctx.client(
        "athena",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return client, assumed["AssumedRoleUser"]["Arn"]


def _assume_role_with_retry(sts, role_arn: str, session_name: str, timeout_s: float = 60.0):
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                raise
            last_exc = e
            time.sleep(3)
    raise AssertionError(f"could not assume role {role_arn} within {timeout_s}s: {last_exc}")


def _run_query(athena, sql: str, database: str | None, output_location: str, timeout_s: float = 90.0):
    kwargs: dict[str, Any] = {"QueryString": sql, "ResultConfiguration": {"OutputLocation": output_location}}
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    qid = athena.start_query_execution(**kwargs)["QueryExecutionId"]
    deadline = time.monotonic() + timeout_s
    state = None
    reason = None
    while time.monotonic() < deadline:
        resp = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        state = resp["Status"]["State"]
        reason = resp["Status"].get("StateChangeReason")
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return qid, state, reason
        time.sleep(1.5)
    raise AssertionError(f"query {qid} did not reach a terminal state within {timeout_s}s (last={state})")


def _select_rows(athena, qid: str) -> list:
    rows = []
    paginator = athena.get_paginator("get_query_results")
    for page in paginator.paginate(QueryExecutionId=qid):
        for row in page["ResultSet"]["Rows"]:
            rows.append([d.get("VarCharValue") for d in row["Data"]])
    return rows[1:]  # first row is the column header for SELECT statements


def _error_code(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected get_query_results to fail, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
