"""start-data-quality-evaluation-run-conflict-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-data-quality-evaluation-run-conflict-rejected"
GROUP = "error-semantics"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Reusing a ClientToken for StartDataQualityRulesetEvaluationRun with different RulesetNames
    returns ConflictException (idempotency-token mismatch); a fresh ClientToken for the same
    request succeeds (positive control)."""
    glue = ctx.client("glue")
    role_arn = _ensure_glue_role(ctx)
    table = _create_dq_table(ctx)
    ruleset_name = ctx.unique_name("sim2real-glue-ruleset-")
    glue.create_data_quality_ruleset(
        Name=ruleset_name,
        Ruleset="Rules = [ ColumnCount > 0 ]",
        TargetTable={"DatabaseName": table["database"], "TableName": table["table"]},
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _safe_delete_ruleset(ctx, ruleset_name))
    ruleset_name2 = ctx.unique_name("sim2real-glue-ruleset2-")
    glue.create_data_quality_ruleset(
        Name=ruleset_name2,
        Ruleset="Rules = [ ColumnCount > 0 ]",
        TargetTable={"DatabaseName": table["database"], "TableName": table["table"]},
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _safe_delete_ruleset(ctx, ruleset_name2))
    data_source = {"GlueTable": {"DatabaseName": table["database"], "TableName": table["table"]}}
    client_token = ctx.unique_name("sim2real-dq-eval-token-")

    run_id_1 = _retry_until_role_usable(
        lambda: glue.start_data_quality_ruleset_evaluation_run(
            DataSource=data_source, Role=role_arn, RulesetNames=[ruleset_name], ClientToken=client_token
        )
    )["RunId"]
    ctx.on_cleanup(lambda: _safe_cancel_evaluation(ctx, run_id_1))

    # same ClientToken, different RulesetNames -> must be rejected as a mismatch
    code, message = _refusal(
        lambda: glue.start_data_quality_ruleset_evaluation_run(
            DataSource=data_source, Role=role_arn, RulesetNames=[ruleset_name2], ClientToken=client_token
        )
    )
    assert code == "ConflictException", code
    assert message == f"Idempotent start Data Quality run with token {client_token}", message

    # effect absent: the original run is still the one that is tracked
    status1 = glue.get_data_quality_ruleset_evaluation_run(RunId=run_id_1)["Status"]
    assert status1 in ("STARTING", "RUNNING", "SUCCEEDED"), f"run {run_id_1} status after rejected conflict: {status1}"

    # positive control: a fresh ClientToken for the same request is accepted
    run_id_2 = glue.start_data_quality_ruleset_evaluation_run(
        DataSource=data_source,
        Role=role_arn,
        RulesetNames=[ruleset_name],
        ClientToken=ctx.unique_name("sim2real-dq-eval-token2-"),
    )["RunId"]
    ctx.on_cleanup(lambda: _safe_cancel_evaluation(ctx, run_id_2))
    assert run_id_2 != run_id_1, f"fresh ClientToken run {run_id_2} must not reuse the rejected run's id {run_id_1}"


def _refusal(call):
    """(code, message) of a call that MUST be refused; raises when the call succeeds."""
    try:
        call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to be refused but it SUCCEEDED")


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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
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


def _create_dq_table(ctx):
    s3 = ctx.client("s3")
    glue = ctx.client("glue")
    bucket = ctx.unique_name("sim2real-glue-dq-").lower()
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

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

    db_name = ctx.unique_name("sim2real_glue_dq_db_").replace("-", "_")
    glue.create_database(
        DatabaseInput={"Name": db_name}, Tags={"sim2real-check": CHECK}
    )
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


def _wait_terminal(ctx, kind, run_id, terminal_states, timeout_s=180.0, interval_s=5.0):
    glue = ctx.client("glue")
    getter = (
        glue.get_data_quality_rule_recommendation_run
        if kind == "recommendation"
        else glue.get_data_quality_ruleset_evaluation_run
    )
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = getter(RunId=run_id)["Status"]
        if last in terminal_states:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{kind} run {run_id} never reached {terminal_states}; last={last}")


def _safe_delete_database(ctx, db_name):
    try:
        ctx.client("glue").delete_database(Name=db_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _safe_delete_ruleset(ctx, ruleset_name):
    try:
        ctx.client("glue").delete_data_quality_ruleset(Name=ruleset_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _safe_cancel_evaluation(ctx, run_id):
    try:
        ctx.client("glue").cancel_data_quality_ruleset_evaluation_run(RunId=run_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
