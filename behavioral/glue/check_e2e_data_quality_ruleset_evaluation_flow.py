"""e2e-data-quality-ruleset-evaluation-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-data-quality-ruleset-evaluation-flow"
GROUP = "e2e"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Start a ruleset evaluation run against a table with known data, poll until
    terminal, and assert GetDataQualityResult reports the exact pass/fail mix that the
    underlying data implies -- not just that the run reached a terminal status."""
    glue = ctx.client("glue")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    prefix = "dq-data"
    # 3 rows: 2 ACTIVE, 1 INACTIVE.
    s3.put_object(
        Bucket=bucket,
        Key=f"{prefix}/data.csv",
        Body=b"id,status\n1,ACTIVE\n2,ACTIVE\n3,INACTIVE\n",
    )
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=f"{prefix}/data.csv"))

    role_arn = _create_glue_role(ctx)

    db_name = ctx.unique_name("sim2real-behav-dqdb-")
    table_name = ctx.unique_name("sim2real-behav-dqtbl-")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "Parameters": {"classification": "csv", "skip.header.line.count": "1"},
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "int"}, {"Name": "status", "Type": "string"}],
                "Location": f"s3://{bucket}/{prefix}/",
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

    ruleset_name = ctx.unique_name("sim2real-behav-dqrs-")
    ruleset_dqdl = (
        'Rules = [ RowCount = 3, RowCount = 999, '
        'ColumnValues "status" in [ "ACTIVE", "INACTIVE" ] ]'
    )
    glue.create_data_quality_ruleset(
        Name=ruleset_name,
        Ruleset=ruleset_dqdl,
        TargetTable={"TableName": table_name, "DatabaseName": db_name},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_data_quality_ruleset(Name=ruleset_name))

    run_id = _start_evaluation_with_retry(ctx, db_name, table_name, role_arn, ruleset_name)

    final_status = _poll_until(
        lambda: glue.get_data_quality_ruleset_evaluation_run(RunId=run_id)["Status"],
        lambda s: s in {"SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT"},
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert final_status == "SUCCEEDED", f"ruleset evaluation run ended in {final_status}"

    run_details = glue.get_data_quality_ruleset_evaluation_run(RunId=run_id)
    result_ids = run_details["ResultIds"]
    assert len(result_ids) == 1, f"expected exactly one linked result id, got {result_ids}"

    result = glue.get_data_quality_result(ResultId=result_ids[0])
    rule_results = result["RuleResults"]
    assert len(rule_results) == 3, f"expected 3 rule results, got {len(rule_results)}"

    pass_count = sum(1 for r in rule_results if r["Result"] == "PASS")
    fail_count = sum(1 for r in rule_results if r["Result"] == "FAIL")
    assert pass_count == 2, f"expected 2 passing rules (RowCount=3, ColumnValues), got {pass_count}"
    assert fail_count == 1, f"expected 1 failing rule (RowCount=999), got {fail_count}"

    score = result["Score"]
    assert abs(score - (2.0 / 3.0)) < 0.02, f"expected score ~= 0.667 (2 of 3 rules passed), got {score}"


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-dq-").lower().replace("_", "-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _create_glue_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-dqrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
        )
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess")
    )
    return role_arn


def _start_evaluation_with_retry(ctx, db_name, table_name, role_arn, ruleset_name, timeout_s=60.0):
    glue = ctx.client("glue")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return glue.start_data_quality_ruleset_evaluation_run(
                DataSource={"GlueTable": {"DatabaseName": db_name, "TableName": table_name}},
                Role=role_arn,
                RulesetNames=[ruleset_name],
            )["RunId"]
        except Exception as exc:  # role/IAM propagation delay
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"could not start ruleset evaluation run after retries: {last_exc}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
