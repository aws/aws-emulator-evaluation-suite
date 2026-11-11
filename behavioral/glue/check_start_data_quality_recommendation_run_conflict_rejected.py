"""start-data-quality-recommendation-run-conflict-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-data-quality-recommendation-run-conflict-rejected"
GROUP = "error-semantics"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Reusing a ClientToken for StartDataQualityRuleRecommendationRun with a different DataSource
    returns ConflictException (idempotency-token mismatch); once the first run is cancelled, a
    fresh call with a new token succeeds (positive control)."""
    glue = ctx.client("glue")
    role_arn = _ensure_glue_role(ctx)
    table = _create_dq_table(ctx)
    table2_name = _create_second_table(ctx, table)
    data_source = {"GlueTable": {"DatabaseName": table["database"], "TableName": table["table"]}}
    data_source2 = {"GlueTable": {"DatabaseName": table["database"], "TableName": table2_name}}
    client_token = ctx.unique_name("sim2real-dq-rec-token-")

    run_id_1 = _retry_until_role_usable(
        lambda: glue.start_data_quality_rule_recommendation_run(
            DataSource=data_source, Role=role_arn, ClientToken=client_token
        )
    )["RunId"]
    ctx.on_cleanup(lambda: _safe_cancel_recommendation(ctx, run_id_1))

    # same ClientToken, different DataSource -> must be rejected as a mismatch
    code, message = _refusal(
        lambda: glue.start_data_quality_rule_recommendation_run(
            DataSource=data_source2, Role=role_arn, ClientToken=client_token
        )
    )
    assert code == "ConflictException", f"expected ConflictException for the mismatched token, got {code!r}"
    assert message == f"Idempotent start Data Quality run with token {client_token}", message

    # effect absent: no second run was created for the mismatched request
    status1 = glue.get_data_quality_rule_recommendation_run(RunId=run_id_1)["Status"]
    assert status1 in ("STARTING", "RUNNING", "SUCCEEDED"), (
        f"run {run_id_1} should be unaffected by the rejected mismatch, got status={status1!r}"
    )

    # restore: cancel the first run and wait it out so the same target has no active
    # run left -- otherwise a fresh token on the same DataSource would itself collide
    # with run_id_1 on "already active", not exercise the token-mismatch path.
    glue.cancel_data_quality_rule_recommendation_run(RunId=run_id_1)
    _wait_terminal(ctx, "recommendation", run_id_1, ("STOPPED", "SUCCEEDED", "FAILED", "TIMEOUT"))

    # positive control: a fresh ClientToken for the same request is accepted
    run_id_2 = glue.start_data_quality_rule_recommendation_run(
        DataSource=data_source, Role=role_arn, ClientToken=ctx.unique_name("sim2real-dq-rec-token2-")
    )["RunId"]
    ctx.on_cleanup(lambda: _safe_cancel_recommendation(ctx, run_id_2))
    assert run_id_2 != run_id_1, "fresh ClientToken must not replay the mismatched run's id"

    # terminal read: independent GetDataQualityRuleRecommendationRun, not the start call's own response
    status2 = glue.get_data_quality_rule_recommendation_run(RunId=run_id_2)["Status"]
    assert status2 in ("STARTING", "RUNNING", "SUCCEEDED"), (
        f"run_id_2 {run_id_2} did not actually start, got status={status2!r}"
    )


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
    # us-east-1 is S3's API-level default region: CreateBucketConfiguration must be
    # omitted there and is required everywhere else -- not a region pin on the check.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

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
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
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


def _create_second_table(ctx, table):
    glue = ctx.client("glue")
    table_name = "sample_tbl2"
    glue.create_table(
        DatabaseName=table["database"],
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "string"}, {"Name": "value", "Type": "string"}],
                "Location": f"s3://{table['bucket']}/data/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                    "Parameters": {"field.delim": ","},
                },
            },
        },
    )
    return table_name


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


def _safe_cancel_recommendation(ctx, run_id):
    try:
        ctx.client("glue").cancel_data_quality_rule_recommendation_run(RunId=run_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
