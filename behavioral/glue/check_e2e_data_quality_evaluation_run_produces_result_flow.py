"""e2e-data-quality-evaluation-run-produces-result-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-data-quality-evaluation-run-produces-result-flow"
GROUP = "e2e"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A data quality ruleset evaluation run on a catalog table SUCCEEDS with one result whose two
    rules split PASS/FAIL on the real row count (RowCount metric equal to it) and whose Score is
    about 0.5.
    """
    glue = ctx.client("glue")
    bucket = _create_bucket(ctx)
    database_name = ctx.unique_name("sim2real_dq_db_").replace("-", "_")
    table_name = ctx.unique_name("sim2real_dq_tbl_").replace("-", "_")
    row_count = 20
    rows = [(i, f"cat{i % 4}") for i in range(1, row_count + 1)]
    _create_csv_table(ctx, database_name, table_name, bucket, "data", [("id", "int"), ("category", "string")], rows)
    role_arn = _create_glue_role(ctx, bucket)

    wrong_row_count = row_count + 999
    ruleset_name = ctx.unique_name("sim2real-ruleset-")
    # Two rules in one run so the result must show a genuine pass/fail split: a stub that
    # echoes the ruleset text without evaluating it against the actual row count cannot
    # produce this mix, since wrong_row_count never matches the 20 real rows.
    ruleset_body = f"Rules = [ RowCount = {row_count}, RowCount = {wrong_row_count} ]"
    glue.create_data_quality_ruleset(
        Name=ruleset_name,
        Ruleset=ruleset_body,
        TargetTable={"TableName": table_name, "DatabaseName": database_name},
    )
    ctx.on_cleanup(lambda: glue.delete_data_quality_ruleset(Name=ruleset_name))

    run_id = _retry_role_propagation(
        lambda: glue.start_data_quality_ruleset_evaluation_run(
            DataSource={"GlueTable": {"DatabaseName": database_name, "TableName": table_name}},
            Role=role_arn,
            RulesetNames=[ruleset_name],
        )
    )["RunId"]

    run_status = _poll_until(
        lambda: glue.get_data_quality_ruleset_evaluation_run(RunId=run_id),
        lambda r: r["Status"] in ("SUCCEEDED", "FAILED", "STOPPED"),
        timeout_s=600.0,
        interval_s=15.0,
    )
    assert run_status["Status"] == "SUCCEEDED", f"evaluation run did not succeed: {run_status}"
    result_ids = run_status["ResultIds"]
    assert len(result_ids) == 1, f"expected exactly one linked result id, got: {result_ids}"

    result = glue.get_data_quality_result(ResultId=result_ids[0])
    assert result["RulesetName"] == ruleset_name, f"expected ruleset {ruleset_name!r}, got {result['RulesetName']!r}"
    rule_results = result["RuleResults"]
    assert len(rule_results) == 2, f"expected 2 rule results, got {rule_results}"
    passing = [r for r in rule_results if r["Result"] == "PASS"]
    failing = [r for r in rule_results if r["Result"] == "FAIL"]
    assert len(passing) == 1, f"expected exactly 1 passing rule, got {rule_results}"
    assert len(failing) == 1, f"expected exactly 1 failing rule, got {rule_results}"
    assert str(row_count) in passing[0]["Description"], passing[0]
    assert str(wrong_row_count) in failing[0]["Description"], failing[0]
    assert passing[0]["EvaluatedMetrics"]["Dataset.*.RowCount"] == float(row_count), passing[0]
    assert abs(result["Score"] - 0.5) < 0.02, f"expected score ~0.5 (1 of 2 rules passed), got {result['Score']}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _retry_role_propagation(fn, *, timeout_s=90.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            last_err = err
            code = err.response["Error"]["Code"]
            if code in ("AccessDeniedException", "InvalidInputException"):
                time.sleep(interval_s)
                continue
            raise
    if last_err is not None:
        raise last_err
    raise AssertionError("retry_role_propagation exhausted without an error to raise")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-glue-dq-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    return bucket


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _create_csv_table(ctx, database_name, table_name, bucket, key_prefix, columns, rows):
    s3 = ctx.client("s3")
    glue = ctx.client("glue")
    body = "\n".join(",".join(str(v) for v in row) for row in rows) + "\n"
    s3.put_object(Bucket=bucket, Key=f"{key_prefix}/data.csv", Body=body.encode())
    glue.create_database(DatabaseInput={"Name": database_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=database_name))
    glue.create_table(
        DatabaseName=database_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [{"Name": c, "Type": t} for c, t in columns],
                "Location": f"s3://{bucket}/{key_prefix}/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                    "Parameters": {"field.delim": ","},
                },
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=database_name, Name=table_name))


def _create_glue_role(ctx, bucket):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-dq-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn))
    s3_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-s3-access", PolicyDocument=json.dumps(s3_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-s3-access"))
    return role["Role"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
