"""table-optimizer-lifecycle-create-get-delete-404."""
from __future__ import annotations

import json
import re

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "table-optimizer-lifecycle-create-get-delete-404"
GROUP = "state-machine"
SERVICES = ["glue"]

#: The suffix Glue appends to each refusal; the request id differs per call.
_GLUE_404 = " (Service: glue; Status Code: 404; Error Code: EntityNotFoundException; Request ID: {rid}; Proxy: null)"


def _filled(template, message):
    """`template` with its {rid} slots filled, in order, from the request ids `message` carries:
    the per-call part each wrapped service appends."""
    rids = iter(re.findall(r"Request ID: ([0-9a-f-]+);", message or ""))
    return re.sub(r"\{rid\}", lambda m: next(rids, "?"), template)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTableOptimizer returns a created compaction optimizer with its roleArn and enabled=False;
    after DeleteTableOptimizer, Get and a repeat Delete raise EntityNotFoundException with their
    exact messages.
    """
    glue = ctx.client("glue")
    sts = ctx.client("sts")
    catalog_id = sts.get_caller_identity()["Account"]
    role_arn = _create_glue_role(ctx)

    db_name = ctx.unique_name("sim2real_db_")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: _tolerate_not_found(lambda: glue.delete_database(Name=db_name)))

    bucket_name = _create_bucket(ctx)

    table_name = ctx.unique_name("sim2real_tbl_")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "int"}],
                "Location": f"s3://{bucket_name}/{table_name}/",
            },
        },
        OpenTableFormatInput={"IcebergInput": {"MetadataOperation": "CREATE", "Version": "2"}},
    )
    ctx.on_cleanup(
        lambda: _tolerate_not_found(lambda: glue.delete_table(DatabaseName=db_name, Name=table_name))
    )

    _retry_on_role_propagation(
        lambda: glue.create_table_optimizer(
            CatalogId=catalog_id,
            DatabaseName=db_name,
            TableName=table_name,
            Type="compaction",
            TableOptimizerConfiguration={
                "roleArn": role_arn,
                "enabled": False,
                "compactionConfiguration": {"icebergConfiguration": {"strategy": "binpack"}},
            },
        )
    )

    ctx.on_cleanup(
        lambda: _tolerate_not_found(
            lambda: glue.delete_table_optimizer(
                CatalogId=catalog_id, DatabaseName=db_name, TableName=table_name, Type="compaction"
            )
        )
    )

    got = glue.get_table_optimizer(
        CatalogId=catalog_id, DatabaseName=db_name, TableName=table_name, Type="compaction"
    )
    got_type = got["TableOptimizer"]["type"]
    assert got_type == "compaction", f"expected type=compaction, got {got_type!r}"
    got_role_arn = got["TableOptimizer"]["configuration"]["roleArn"]
    assert got_role_arn == role_arn, f"expected roleArn={role_arn!r}, got {got_role_arn!r}"
    got_enabled = got["TableOptimizer"]["configuration"]["enabled"]
    assert got_enabled is False, f"expected enabled=False, got {got_enabled!r}"

    glue.delete_table_optimizer(
        CatalogId=catalog_id, DatabaseName=db_name, TableName=table_name, Type="compaction"
    )

    code, message = _refusal(
        lambda: glue.get_table_optimizer(
            CatalogId=catalog_id, DatabaseName=db_name, TableName=table_name, Type="compaction"
        )
    )
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException after delete, got {code!r}"
    assert message == _filled(
        f"No optimizer of type compaction found for the table: {table_name}{_GLUE_404}", message
    ), f"unexpected not-found message {message!r}"

    redelete_code, redelete_message = _refusal(
        lambda: glue.delete_table_optimizer(
            CatalogId=catalog_id, DatabaseName=db_name, TableName=table_name, Type="compaction"
        )
    )
    assert redelete_code == "EntityNotFoundException", (
        f"expected a second delete of the already-deleted optimizer to also raise "
        f"EntityNotFoundException, got {redelete_code!r}"
    )
    assert redelete_message == _filled(
        f"An optimizer of type compaction does not exist on table {table_name}{_GLUE_404}",
        redelete_message,
    ), f"unexpected not-found message {redelete_message!r}"


def _refusal(call):
    """(code, message) of a call that MUST be refused; raises when the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError("the call was expected to be refused but it SUCCEEDED")


def _tolerate_not_found(call):
    """Teardown: a resource the check already deleted is not an error."""
    from botocore.exceptions import ClientError

    try:
        call()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "EntityNotFoundException":
            raise


def _retry_on_role_propagation(fn, timeout_s=90.0):
    import time
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "InvalidInputException") and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _create_glue_role(ctx):
    import time

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    s3_policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=s3_policy_arn)

    def _cleanup():
        for p in (policy_arn, s3_policy_arn):
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=p)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)

    deadline = time.monotonic() + 30
    while iam.get_role(RoleName=role_name)["Role"]["Arn"] != arn and time.monotonic() < deadline:
        time.sleep(2)
    return arn


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    region = s3.meta.region_name
    bucket_name = ctx.unique_name("sim2real-glue-optimizer-").lower().replace("_", "-")
    if region and region != "us-east-1":
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region})
    else:
        s3.create_bucket(Bucket=bucket_name)
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket_name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket_name)

    ctx.on_cleanup(_cleanup)
    return bucket_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
