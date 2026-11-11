"""create-table-optimizer-nonexistent-table-not-found."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "create-table-optimizer-nonexistent-table-not-found"
GROUP = "error-semantics"
SERVICES = ["glue"]

#: AWS's not-found wording; each wrapped service appends its per-call request id.
_ENTITY_NOT_FOUND = (
    "Entity Not Found (Service: AmazonDataCatalog; Status Code: 400; Error Code: EntityNotFoundException; "
    "Request ID: {rid}; Proxy: null) (Service: glue; Status Code: 404; Error Code: EntityNotFoundException; "
    "Request ID: {rid}; Proxy: null)"
)


def _filled(template, message):
    """`template` with its {rid} slots filled, in order, from the request ids `message` carries:
    the per-call part each wrapped service appends."""
    rids = iter(re.findall(r"Request ID: ([0-9a-f-]+);", message or ""))
    return re.sub(r"\{rid\}", lambda m: next(rids, "?"), template)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create- and GetTableOptimizer on a table that does not exist raise EntityNotFoundException
    with the exact message, while on a real Iceberg table CreateTableOptimizer succeeds and
    GetTableOptimizer returns its roleArn and enabled=False.
    """
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    iam = ctx.client("iam")

    account_id = sts.get_caller_identity()["Account"]
    role_arn = _create_optimizer_role(ctx, iam)

    bucket = ctx.unique_name("sim2real-glue-topt-").lower()
    # us-east-1 rejects CreateBucket with an explicit LocationConstraint for that region;
    # every other region requires one. This branches on ctx.region, not a hardcoded target region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    db_name = ctx.unique_name("sim2realgluetoptdb").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    missing_table = ctx.unique_name("sim2realgluetopt_missing").replace("-", "_")

    # Negative: the target table does not exist in the database. The freshly created role's
    # trust policy can take a few seconds to propagate, during which Glue returns
    # AccessDeniedException instead of validating the table -- retry through that window so
    # we observe the real EntityNotFoundException outcome.
    code, message = _retry_on_role_propagation(
        lambda: glue.create_table_optimizer(
            CatalogId=account_id,
            DatabaseName=db_name,
            TableName=missing_table,
            Type="compaction",
            TableOptimizerConfiguration={"roleArn": role_arn, "enabled": False},
        )
    )
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code!r}"
    assert message == _filled(_ENTITY_NOT_FOUND, message), f"unexpected not-found message {message!r}"

    # Effect absent: no optimizer configuration was persisted for the missing table.
    get_code, get_message = _error_code(
        lambda: glue.get_table_optimizer(
            CatalogId=account_id, DatabaseName=db_name, TableName=missing_table, Type="compaction"
        )
    )
    assert get_code == "EntityNotFoundException", f"expected EntityNotFoundException, got {get_code!r}"
    assert get_message == _filled(_ENTITY_NOT_FOUND, get_message), f"unexpected not-found message {get_message!r}"

    # Positive control: creating a table optimizer on a real Iceberg table succeeds.
    real_table = ctx.unique_name("sim2realgluetopt_real").replace("-", "_")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": real_table,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [{"Name": "col1", "Type": "string"}],
                "Location": f"s3://{bucket}/iceberg/{real_table}/",
            },
        },
        OpenTableFormatInput={"IcebergInput": {"MetadataOperation": "CREATE", "Version": "2"}},
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=real_table))

    create_code, _ = _retry_on_role_propagation(
        lambda: glue.create_table_optimizer(
            CatalogId=account_id,
            DatabaseName=db_name,
            TableName=real_table,
            Type="compaction",
            TableOptimizerConfiguration={"roleArn": role_arn, "enabled": False},
        )
    )
    assert create_code is None, f"expected CreateTableOptimizer to succeed, got error {create_code!r}"
    ctx.on_cleanup(
        lambda: glue.delete_table_optimizer(
            CatalogId=account_id, DatabaseName=db_name, TableName=real_table, Type="compaction"
        )
    )

    optimizer = _poll_until(
        lambda: _get_table_optimizer_or_none(glue, account_id, db_name, real_table),
        lambda opt: opt is not None,
        timeout_s=30,
        interval_s=3,
    )
    assert optimizer["configuration"]["roleArn"] == role_arn, (
        f"expected persisted roleArn {role_arn!r}, got {optimizer['configuration'].get('roleArn')!r}"
    )
    assert optimizer["configuration"]["enabled"] is False, (
        f"expected persisted enabled=False, got {optimizer['configuration'].get('enabled')!r}"
    )


def _error_code(fn):
    """Return (code, message) of the ClientError fn() raises; raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _retry_on_role_propagation(fn, timeout_s=90.0):
    """Call fn(); if it raises AccessDeniedException/InvalidInputException (IAM role trust
    propagation lag), retry until timeout_s. Returns the terminal (code, message), or
    (None, None) on success."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return None, None
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "InvalidInputException") and time.monotonic() < deadline:
                time.sleep(5)
                continue
            return code, e.response["Error"].get("Message", "")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _get_table_optimizer_or_none(glue, account_id, db_name, table_name):
    from botocore.exceptions import ClientError

    try:
        return glue.get_table_optimizer(
            CatalogId=account_id, DatabaseName=db_name, TableName=table_name, Type="compaction"
        )["TableOptimizer"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityNotFoundException":
            return None
        raise


def _empty_and_delete_bucket(s3, bucket):
    """The Iceberg CREATE writes table metadata under the bucket, so empty it before deleting."""
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
    s3.delete_bucket(Bucket=bucket)


def _create_optimizer_role(ctx, iam):
    from botocore.exceptions import ClientError

    role_name = ctx.unique_name("sim2real-glue-topt-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
        )
    )
    s3_policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=s3_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=s3_policy_arn))
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            if iam.get_role(RoleName=role_name)["Role"]["Arn"] == role["Arn"]:
                break
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise
        time.sleep(2)
    return role["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

