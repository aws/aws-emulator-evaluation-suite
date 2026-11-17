"""cancel-ml-task-run-nonexistent-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-ml-task-run-nonexistent-rejected"
GROUP = "negative-classes"
SERVICES = ["glue", "iam", "s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelMLTaskRun names the missing TransformId when it does not exist, and the missing
    TaskRunId (against a real transform) when only the task run does not exist.

    Reference: https://docs.aws.amazon.com/glue/latest/webapi/API_CancelMLTaskRun.html
    """
    glue = ctx.client("glue")
    role_arn = _create_glue_role(ctx)
    db_name, table_name = _create_ml_table(ctx)

    transform_id = _retry_until_role_usable(
        lambda: glue.create_ml_transform(
            Name=ctx.unique_name("sim2real-cmltr-"),
            InputRecordTables=[{"DatabaseName": db_name, "TableName": table_name}],
            Parameters={"TransformType": "FIND_MATCHES", "FindMatchesParameters": {"PrimaryKeyColumnName": "id"}},
            Role=role_arn,
        )
    )["TransformId"]
    ctx.on_cleanup(_safe_delete_ml_transform(glue, transform_id))

    # Positive control: the real transform is reachable through an independent read.
    desc = glue.get_ml_transform(TransformId=transform_id)
    assert desc["TransformId"] == transform_id, (
        f"expected GetMLTransform to echo TransformId {transform_id!r}, got {desc.get('TransformId')!r}"
    )

    bogus_task_run_id = ctx.unique_name("sim2real-cmltr-taskrun-")
    code1, message1 = _refusal(
        lambda: glue.cancel_ml_task_run(TransformId=transform_id, TaskRunId=bogus_task_run_id)
    )
    assert code1 == "EntityNotFoundException", f"expected EntityNotFoundException, got {code1}"
    assert message1 == (
        f"No ML Task Run found for {bogus_task_run_id}: in account {ctx.account} for transform {transform_id}"
    ), f"unexpected CancelMLTaskRun message for a missing task run: {message1!r}"

    bogus_transform_id = ctx.unique_name("sim2real-cmltr-xform-")
    code2, message2 = _refusal(
        lambda: glue.cancel_ml_task_run(TransformId=bogus_transform_id, TaskRunId=bogus_task_run_id)
    )
    assert code2 == "EntityNotFoundException", f"expected EntityNotFoundException, got {code2}"
    assert message2 == (
        f"Cannot find MLTransform in account {ctx.account} with handle {bogus_transform_id}"
    ), f"unexpected CancelMLTaskRun message for a missing transform: {message2!r}"


def _refusal(fn):
    """Return the (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete_ml_transform(glue, transform_id):
    def _cleanup() -> None:
        try:
            glue.delete_ml_transform(TransformId=transform_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFoundException":
                raise

    return _cleanup


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


def _create_glue_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cmltr-role-")
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

    policy_arns = (
        "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    )
    for policy_arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=p))
    return role_arn


def _create_ml_table(ctx):
    s3 = ctx.client("s3")
    glue = ctx.client("glue")
    bucket = ctx.unique_name("sim2real-cmltr-").lower()
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    db_name = ctx.unique_name("sim2real_cmltr_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    table_name = ctx.unique_name("sim2real_cmltr_tbl_").replace("-", "_")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "string"}, {"Name": "value", "Type": "string"}],
                "Location": f"s3://{bucket}/data/",
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=table_name))
    return db_name, table_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
