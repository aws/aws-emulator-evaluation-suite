"""create-ml-transform-idempotent-token-mismatch-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-ml-transform-idempotent-token-mismatch-rejected"
GROUP = "negative-classes"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateMLTransform reusing a Name with different params is AlreadyExists, original unchanged.

    The request has no ClientToken; Name is the identity key. A distinct Name still succeeds.

    Reference: https://docs.aws.amazon.com/glue/latest/webapi/API_CreateMLTransform.html
    """
    glue = ctx.client("glue")
    role_arn = _create_glue_assumable_role(ctx)
    db_name, table_name = _create_table_with_column(ctx, glue)

    name = ctx.unique_name("sim2real-mlxform-")
    input_tables = [{"DatabaseName": db_name, "TableName": table_name}]
    transform_id = _retry_role_not_assumable(
        lambda: glue.create_ml_transform(
            Name=name,
            Role=role_arn,
            InputRecordTables=input_tables,
            Parameters={
                "TransformType": "FIND_MATCHES",
                "FindMatchesParameters": {"PrimaryKeyColumnName": "col1"},
            },
            MaxRetries=1,
            Tags={"sim2real": CHECK},
        )
    )["TransformId"]
    ctx.on_cleanup(lambda: _best_effort_delete_ml_transform(glue, transform_id))

    original = glue.get_ml_transform(TransformId=transform_id)
    assert original["MaxRetries"] == 1, f"expected freshly-created MaxRetries==1, got {original['MaxRetries']}"

    code, message = _error(
        lambda: glue.create_ml_transform(
            Name=name,
            Role=role_arn,
            InputRecordTables=input_tables,
            Parameters={
                "TransformType": "FIND_MATCHES",
                "FindMatchesParameters": {"PrimaryKeyColumnName": "col1"},
            },
            MaxRetries=9,
        )
    )
    assert code == "AlreadyExistsException", f"expected AlreadyExistsException reusing Name, got {code!r}"
    assert message == f"Transform with name {name} already exists", f"unexpected CreateMLTransform message: {message!r}"

    unchanged = glue.get_ml_transform(TransformId=transform_id)
    assert unchanged["MaxRetries"] == 1, (
        f"expected the rejected create to leave MaxRetries==1, got {unchanged['MaxRetries']}"
    )

    other_name = ctx.unique_name("sim2real-mlxform-ctrl-")
    other_id = glue.create_ml_transform(
        Name=other_name,
        Role=role_arn,
        InputRecordTables=input_tables,
        Parameters={
            "TransformType": "FIND_MATCHES",
            "FindMatchesParameters": {"PrimaryKeyColumnName": "col1"},
        },
        MaxRetries=1,
        Tags={"sim2real": CHECK},
    )["TransformId"]
    ctx.on_cleanup(lambda: _best_effort_delete_ml_transform(glue, other_id))
    created = glue.get_ml_transform(TransformId=other_id)
    assert created["Name"] == other_name, f"expected the distinct-Name create to land as {other_name!r}, got {created.get('Name')!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _retry_role_not_assumable(fn, timeout_s: float = 60.0, interval_s: float = 5.0):
    """Retry fn() while a new IAM role propagates; CreateMLTransform validates it synchronously
    and returns InvalidInputException("Unable to assume role...") or AccessDeniedException."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            transient = code == "AccessDeniedException" or (
                code == "InvalidInputException" and "assume role" in message.lower()
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _best_effort_delete_ml_transform(glue, transform_id: str) -> None:
    try:
        glue.delete_ml_transform(TransformId=transform_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _create_table_with_column(ctx, glue) -> tuple[str, str]:
    db_name = ctx.unique_name("sim2real-db-")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    table_name = ctx.unique_name("sim2real-tbl-")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "StorageDescriptor": {
                "Columns": [
                    {"Name": "col1", "Type": "string"},
                    {"Name": "col2", "Type": "string"},
                ],
                "Location": f"s3://sim2real-nonexistent-{ctx.unique_name('bucket-')}/data/",
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=table_name))
    return db_name, table_name


def _create_glue_assumable_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-mlxform-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # FIND_MATCHES provisions a temp S3 bucket with this role; AWSGlueServiceRole lacks
    # s3:CreateBucket, so attach S3 access too.
    glue_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=glue_policy_arn)
    ctx.on_cleanup(lambda: _best_effort_detach_policy(iam, role_name, glue_policy_arn))

    s3_policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=s3_policy_arn)
    ctx.on_cleanup(lambda: _best_effort_detach_policy(iam, role_name, s3_policy_arn))

    return role_arn


def _best_effort_detach_policy(iam, role_name: str, policy_arn: str) -> None:
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
