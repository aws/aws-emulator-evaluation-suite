"""data-quality-ruleset-evaluation-run-lookup-rejections."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-quality-ruleset-evaluation-run-lookup-rejections"
GROUP = "negative-classes"
SERVICES = ["glue", "iam", "s3"]

_TERMINAL = ("STOPPED", "SUCCEEDED", "FAILED", "TIMEOUT")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Get/CancelDataQualityRulesetEvaluationRun raise InvalidInputException for a RunId outside
    the 'dqrun-' shape and EntityNotFoundException for one in shape but never issued;
    BatchGetDataQualityRulesetEvaluationRun instead reports the latter in RunsNotFound.

    Reference: https://docs.aws.amazon.com/glue/latest/webapi/API_GetDataQualityRulesetEvaluationRun.html
    """
    glue = ctx.client("glue")
    role_arn = _create_glue_role(ctx)
    bucket = _create_bucket(ctx)
    db_name, table_name = _create_table(ctx, bucket)
    ruleset_name = _create_ruleset(ctx, db_name, table_name)
    data_source = {"GlueTable": {"DatabaseName": db_name, "TableName": table_name}}

    run_id = _retry_until_role_usable(
        lambda: glue.start_data_quality_ruleset_evaluation_run(
            DataSource=data_source, Role=role_arn, RulesetNames=[ruleset_name], NumberOfWorkers=2
        )
    )["RunId"]
    ctx.on_cleanup(_safe_cancel_and_wait(glue, run_id))

    # Positive control: the real run is reachable through GetDataQualityRulesetEvaluationRun.
    got = glue.get_data_quality_ruleset_evaluation_run(RunId=run_id)
    assert got["RunId"] == run_id, f"expected RunId {run_id!r}, got {got.get('RunId')!r}"
    assert got["RulesetNames"] == [ruleset_name], (
        f"expected RulesetNames [{ruleset_name!r}], got {got.get('RulesetNames')!r}"
    )

    not_found_id = f"dqrun-{uuid.uuid4().hex}"

    # Positive control: BatchGet partitions a real run into Runs and an absent one into
    # RunsNotFound, through a third operation independent of Get and Cancel.
    batch = glue.batch_get_data_quality_ruleset_evaluation_run(RunIds=[run_id, not_found_id])
    assert [r["RunId"] for r in batch["Runs"]] == [run_id], (
        f"expected Runs to contain only {run_id!r}, got {[r.get('RunId') for r in batch['Runs']]!r}"
    )
    assert batch["RunsNotFound"] == [not_found_id], (
        f"expected RunsNotFound [{not_found_id!r}], got {batch.get('RunsNotFound')!r}"
    )

    malformed_id = "sim2real-" + uuid.uuid4().hex

    # Negative: a RunId outside the 'dqrun-' shape is a format rejection, not a lookup.
    get_malformed = _refusal(lambda: glue.get_data_quality_ruleset_evaluation_run(RunId=malformed_id))
    assert get_malformed == ("InvalidInputException", "Invalid RunId: must start with 'dqrun-'"), (
        f"unexpected GetDataQualityRulesetEvaluationRun message for a malformed id: {get_malformed!r}"
    )
    cancel_malformed = _refusal(lambda: glue.cancel_data_quality_ruleset_evaluation_run(RunId=malformed_id))
    assert cancel_malformed == ("InvalidInputException", "Invalid RunId: must start with 'dqrun-'"), (
        f"unexpected CancelDataQualityRulesetEvaluationRun message for a malformed id: {cancel_malformed!r}"
    )
    batch_malformed = _refusal(
        lambda: glue.batch_get_data_quality_ruleset_evaluation_run(RunIds=[malformed_id])
    )
    assert batch_malformed == ("InvalidInputException", ""), (
        f"unexpected BatchGetDataQualityRulesetEvaluationRun error for a malformed id: {batch_malformed!r}"
    )

    # Negative: a well-shaped RunId that was never issued is a lookup failure, naming it exactly.
    get_absent = _refusal(lambda: glue.get_data_quality_ruleset_evaluation_run(RunId=not_found_id))
    assert get_absent == (
        "EntityNotFoundException",
        f"Cannot find Data Quality Run in account {ctx.account} with id {not_found_id}",
    ), f"unexpected GetDataQualityRulesetEvaluationRun message for an absent id: {get_absent!r}"
    cancel_absent = _refusal(lambda: glue.cancel_data_quality_ruleset_evaluation_run(RunId=not_found_id))
    assert cancel_absent == (
        "EntityNotFoundException",
        f"Cannot find Data Quality Run in account {ctx.account} with id {not_found_id}",
    ), f"unexpected CancelDataQualityRulesetEvaluationRun message for an absent id: {cancel_absent!r}"


def _refusal(fn):
    """Return the (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _retry_until_role_usable(fn, timeout_s: float = 60.0, interval_s: float = 5.0):
    """IAM role propagation is eventually consistent; retry only the codes that mean that."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "InvalidInputException") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _safe_cancel_and_wait(glue, run_id, timeout_s: float = 120.0):
    """Cancel the run unless it already ended, then wait for a terminal status before deleting
    the catalog resources it still references."""

    def _cleanup() -> None:
        def status():
            return glue.get_data_quality_ruleset_evaluation_run(RunId=run_id)["Status"]

        if status() in _TERMINAL:
            return
        try:
            glue.cancel_data_quality_ruleset_evaluation_run(RunId=run_id)
        except ClientError:
            if status() not in _TERMINAL:
                raise
        deadline = time.monotonic() + timeout_s
        while True:
            last = status()
            if last in _TERMINAL:
                return
            if time.monotonic() >= deadline:
                raise AssertionError(f"run {run_id} did not reach a terminal status (last={last})")
            time.sleep(5)

    return _cleanup


def _create_glue_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-dqrun-role-")
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
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-dqrun-").lower()
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


def _create_table(ctx, bucket: str):
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real_dqrun_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    table_name = ctx.unique_name("sim2real_dqrun_tbl_").replace("-", "_")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "string"}],
                "Location": f"s3://{bucket}/{table_name}/",
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=table_name))
    return db_name, table_name


def _create_ruleset(ctx, db_name: str, table_name: str) -> str:
    glue = ctx.client("glue")
    ruleset_name = ctx.unique_name("sim2real-dqrun-ruleset-")
    glue.create_data_quality_ruleset(
        Name=ruleset_name,
        Ruleset="Rules = [ ColumnCount > 0 ]",
        TargetTable={"DatabaseName": db_name, "TableName": table_name},
    )
    ctx.on_cleanup(lambda: glue.delete_data_quality_ruleset(Name=ruleset_name))
    return ruleset_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
