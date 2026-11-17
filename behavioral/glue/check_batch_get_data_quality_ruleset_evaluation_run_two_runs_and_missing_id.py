"""batch-get-data-quality-ruleset-evaluation-run-two-runs-and-missing-id."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-data-quality-ruleset-evaluation-run-two-runs-and-missing-id"
GROUP = "server-side"
SERVICES = ["glue", "s3", "iam"]


# StartDataQualityRulesetEvaluationRun launches a real Glue Data Quality Spark job; on real AWS
# this is billed compute, so this check runs exactly two of them.
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """BatchGetDataQualityRulesetEvaluationRun returns both evaluation runs this check started,
    keyed by RunId, and groups an id nobody started under RunsNotFound.
    """
    glue = ctx.client("glue")
    bucket, db_name, table_name = _provision_catalog_table(ctx)
    role_arn = _provision_evaluation_role(ctx, bucket)

    ruleset_a = _create_ruleset(ctx, glue, db_name, table_name, "Rules = [ ColumnCount = 2 ]")
    ruleset_b = _create_ruleset(ctx, glue, db_name, table_name, "Rules = [ RowCount between 1 and 100 ]")

    run_id_a = _start_evaluation_run(glue, db_name, table_name, role_arn, ruleset_a, "client-token-a")
    run_id_b = _start_evaluation_run(glue, db_name, table_name, role_arn, ruleset_b, "client-token-b")
    assert run_id_a != run_id_b, f"two independent Start calls produced the same RunId {run_id_a!r}"

    for run_id in (run_id_a, run_id_b):
        final = _poll_until_terminal(glue, run_id)
        assert final["Status"] == "SUCCEEDED", f"evaluation run {run_id!r} did not succeed: {final}"

    missing_run_id = "dqrun-" + ctx.unique_name("sim2realmissing").replace("-", "")[:32].ljust(32, "0")
    batch = glue.batch_get_data_quality_ruleset_evaluation_run(
        RunIds=[run_id_a, run_id_b, missing_run_id]
    )

    found_by_id = {r["RunId"]: r for r in batch.get("Runs", [])}
    assert set(found_by_id) == {run_id_a, run_id_b}, (
        f"expected BatchGet to return exactly the two started runs, got {sorted(found_by_id)}"
    )
    assert found_by_id[run_id_a]["RulesetNames"] == [ruleset_a], (
        f"expected run {run_id_a!r} linked to ruleset {ruleset_a!r}, got {found_by_id[run_id_a]['RulesetNames']!r}"
    )
    assert found_by_id[run_id_b]["RulesetNames"] == [ruleset_b], (
        f"expected run {run_id_b!r} linked to ruleset {ruleset_b!r}, got {found_by_id[run_id_b]['RulesetNames']!r}"
    )
    assert found_by_id[run_id_a]["Status"] == "SUCCEEDED", found_by_id[run_id_a]["Status"]
    assert found_by_id[run_id_b]["Status"] == "SUCCEEDED", found_by_id[run_id_b]["Status"]

    assert batch.get("RunsNotFound") == [missing_run_id], (
        f"expected RunsNotFound to hold exactly the id nobody started, got {batch.get('RunsNotFound')!r}"
    )


def _poll_until_terminal(glue, run_id: str, timeout_s: float = 600.0, interval_s: float = 15.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = glue.get_data_quality_ruleset_evaluation_run(RunId=run_id)
        if last["Status"] not in ("STARTING", "RUNNING"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"run {run_id!r} did not reach a terminal state within {timeout_s}s (last={last!r})")


def _start_evaluation_run(glue, db_name, table_name, role_arn, ruleset_name, token_suffix: str) -> str:
    deadline = time.monotonic() + 90.0
    while True:
        try:
            resp = glue.start_data_quality_ruleset_evaluation_run(
                DataSource={"GlueTable": {"DatabaseName": db_name, "TableName": table_name}},
                Role=role_arn,
                RulesetNames=[ruleset_name],
                ClientToken=f"sim2real-dqe-{token_suffix}",
            )
            return resp["RunId"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "InvalidInputException") and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise


def _create_ruleset(ctx, glue, db_name, table_name, ruleset_text: str) -> str:
    name = ctx.unique_name("sim2real-glue-dqe-ruleset-")
    glue.create_data_quality_ruleset(
        Name=name,
        Ruleset=ruleset_text,
        TargetTable={"DatabaseName": db_name, "TableName": table_name},
    )
    ctx.on_cleanup(lambda: glue.delete_data_quality_ruleset(Name=name))
    return name


def _provision_catalog_table(ctx):
    s3 = ctx.client("s3")
    glue = ctx.client("glue")

    bucket = ctx.unique_name("sim2real-glue-dqe").replace("_", "-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _empty_and_delete_bucket():
        objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objects:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objects]})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_delete_bucket)

    key_prefix = "rows/"
    rows = "\n".join(f"{i},item-{i}" for i in range(1, 11))
    s3.put_object(Bucket=bucket, Key=f"{key_prefix}part-0.csv", Body=rows.encode())

    db_name = ctx.unique_name("sim2real_glue_dqe_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    table_name = ctx.unique_name("sim2real_glue_dqe_tbl_").replace("-", "_")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [{"Name": "item_id", "Type": "string"}, {"Name": "label", "Type": "string"}],
                "Location": f"s3://{bucket}/{key_prefix}",
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


def _provision_evaluation_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-dqe-role-")
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
    iam.put_role_policy(RoleName=role_name, PolicyName="dqe-s3-access", PolicyDocument=json.dumps(inline_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="dqe-s3-access"))

    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
