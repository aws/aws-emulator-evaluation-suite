"""start-data-quality-ruleset-evaluation-run-on-nonexistent-ruleset-fails."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-data-quality-ruleset-evaluation-run-on-nonexistent-ruleset-fails"
GROUP = "overly-permissive"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """StartDataQualityRulesetEvaluationRun naming a never-created ruleset raises
    InvalidInputException and starts no run referencing it; with an existing ruleset it starts one."""
    glue = ctx.client("glue")
    role_arn = _create_glue_service_role(ctx)
    bucket = _create_test_bucket(ctx)

    db_name = ctx.unique_name("sim2real_glue_dq_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: _safe_delete_database(glue, db_name))

    table_name = ctx.unique_name("sim2real_glue_dq_tbl_").replace("-", "_")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [{"Name": "col1", "Type": "string"}],
                "Location": f"s3://{bucket}/{table_name}/",
            },
        },
    )
    ctx.on_cleanup(lambda: _safe_delete_table(glue, db_name, table_name))

    ruleset_name = ctx.unique_name("sim2real-glue-ruleset-")
    glue.create_data_quality_ruleset(
        Name=ruleset_name,
        Ruleset="Rules = [ ColumnCount > 0 ]",
        TargetTable={"DatabaseName": db_name, "TableName": table_name},
    )
    ctx.on_cleanup(lambda: _safe_delete_ruleset(glue, ruleset_name))

    data_source = {"GlueTable": {"DatabaseName": db_name, "TableName": table_name}}

    # Positive control; the role was just created, so retry through IAM propagation.
    run_id = _retry_call(
        lambda: glue.start_data_quality_ruleset_evaluation_run(
            DataSource=data_source, Role=role_arn, RulesetNames=[ruleset_name], NumberOfWorkers=2
        )["RunId"],
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert run_id, "positive control: expected a RunId, got none"
    ctx.on_cleanup(lambda: _safe_cancel_run(glue, run_id))

    # Negative: same call, but the ruleset was never created.
    missing_ruleset = ctx.unique_name("sim2real-glue-missing-ruleset-")
    error = _error_response(
        lambda: glue.start_data_quality_ruleset_evaluation_run(
            DataSource=data_source, Role=role_arn, RulesetNames=[missing_ruleset]
        )
    )
    assert error["Code"] == "InvalidInputException", f"expected InvalidInputException, got {error!r}"
    assert error["Message"] == (
        f"Cannot find Data Quality Ruleset in account {ctx.account} with name {missing_ruleset}"
    ), error

    # Effect absent: no run referencing the missing ruleset was created for this data source.
    listing = glue.list_data_quality_ruleset_evaluation_runs(Filter={"DataSource": data_source})
    for described_run in listing.get("Runs", []):
        assert missing_ruleset not in described_run.get("RulesetNames", []), (
            f"run {described_run.get('RunId')} unexpectedly references the missing ruleset {missing_ruleset!r}"
        )


_GLUE_SERVICE_ROLE_POLICY = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"


def _error_response(fn: Any) -> dict[str, Any]:
    """The Error body of a call that MUST be refused; raises when the call succeeds."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError("the call was expected to be refused but it SUCCEEDED")


def _retry_call(
    fn: Any,
    *,
    timeout_s: float = 60.0,
    interval_s: float = 5.0,
    retry_codes: tuple[str, ...] = ("AccessDeniedException", "InvalidInputException"),
) -> Any:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in retry_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_glue_service_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "glue.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = resp["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_GLUE_SERVICE_ROLE_POLICY)

    def _cleanup() -> None:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=_GLUE_SERVICE_ROLE_POLICY)
        except ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_test_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-glue-dq-").lower()
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup() -> None:
        try:
            token = None
            while True:
                kwargs2: dict[str, Any] = {"Bucket": bucket}
                if token:
                    kwargs2["ContinuationToken"] = token
                resp = s3.list_objects_v2(**kwargs2)
                for obj in resp.get("Contents", []):
                    s3.delete_object(Bucket=bucket, Key=obj["Key"])
                if not resp.get("IsTruncated"):
                    break
                token = resp.get("NextContinuationToken")
            s3.delete_bucket(Bucket=bucket)
        except ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


def _ignore_not_found(fn: Any) -> None:
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _safe_delete_database(glue: Any, db_name: str) -> None:
    _ignore_not_found(lambda: glue.delete_database(Name=db_name))


def _safe_delete_table(glue: Any, db_name: str, table_name: str) -> None:
    _ignore_not_found(lambda: glue.delete_table(DatabaseName=db_name, Name=table_name))


def _safe_delete_ruleset(glue: Any, ruleset_name: str) -> None:
    _ignore_not_found(lambda: glue.delete_data_quality_ruleset(Name=ruleset_name))


_DQ_TERMINAL = ("STOPPED", "SUCCEEDED", "FAILED", "TIMEOUT")


def _safe_cancel_run(glue: Any, run_id: str, timeout_s: float = 120.0) -> None:
    """Cancel the run unless it already ended, then wait for it to end so the deletes that follow succeed."""

    def status() -> str:
        return glue.get_data_quality_ruleset_evaluation_run(RunId=run_id)["Status"]

    if status() in _DQ_TERMINAL:
        return
    try:
        glue.cancel_data_quality_ruleset_evaluation_run(RunId=run_id)
    except ClientError:
        # the run may end between the read and the cancel; anything else is a real failure
        if status() not in _DQ_TERMINAL:
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        last = status()
        if last in _DQ_TERMINAL:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"data quality run {run_id} did not end within {timeout_s}s after cancel (last={last})")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
