"""create-table-optimizer-on-nonexistent-table-fails."""
from __future__ import annotations

import json
import re
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-table-optimizer-on-nonexistent-table-fails"
GROUP = "overly-permissive"
SERVICES = ["glue"]

#: AWS's wording for each refusal; {rid} is what each wrapped service appends per call.
_ENTITY_NOT_FOUND = (
    "Entity Not Found (Service: AmazonDataCatalog; Status Code: 400; Error Code: EntityNotFoundException; "
    "Request ID: {rid}; Proxy: null) (Service: glue; Status Code: 404; Error Code: EntityNotFoundException; "
    "Request ID: {rid}; Proxy: null)"
)
_CREATE_INELIGIBLE = (
    "Glue table metadata filepath is null (Service: glue; Status Code: 400; "
    "Error Code: InvalidInputException; Request ID: {rid}; Proxy: null)"
)


def _filled(template, message):
    """`template` with its {rid} slots filled, in order, from the request ids `message` carries:
    the per-call part each wrapped service appends."""
    rids = iter(re.findall(r"Request ID: ([0-9a-f-]+);", message or ""))
    return re.sub(r"\{rid\}", lambda m: next(rids, "?"), template)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """CreateTableOptimizer on an existing non-Iceberg table raises InvalidInputException, on a
    missing table EntityNotFoundException, and GetTableOptimizer for the missing table also
    raises EntityNotFoundException, so no optimizer persists.
    """
    glue = ctx.client("glue")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = _create_glue_service_role(ctx)

    db_name = ctx.unique_name("sim2real_glue_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: _safe_delete_database(glue, db_name))

    table_name = ctx.unique_name("sim2real_plain_tbl_").replace("-", "_")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Location": f"s3://sim2real-glue-optimizer-probe/{table_name}/",
                "Columns": [{"Name": "id", "Type": "bigint"}],
            },
        },
    )
    ctx.on_cleanup(lambda: _safe_delete_table(glue, db_name, table_name))

    # Positive control: the table genuinely exists but is not an open-table-format
    # (Iceberg) table, so CreateTableOptimizer must reject it for a format reason —
    # a distinct failure mode from "table not found".
    existing_table_code, existing_table_message = _error_code(
        lambda: glue.create_table_optimizer(
            CatalogId=account_id,
            DatabaseName=db_name,
            TableName=table_name,
            Type="compaction",
            TableOptimizerConfiguration={"enabled": False, "roleArn": role_arn},
        )
    )
    assert existing_table_code == "InvalidInputException", (
        f"expected InvalidInputException for an existing non-Iceberg table, "
        f"got {existing_table_code!r}"
    )
    assert existing_table_message == _filled(_CREATE_INELIGIBLE, existing_table_message), existing_table_message

    # Negative: same call, but the table was never created.
    missing_table = ctx.unique_name("sim2real_missing_tbl_").replace("-", "_")
    try:
        glue.create_table_optimizer(
            CatalogId=account_id,
            DatabaseName=db_name,
            TableName=missing_table,
            Type="compaction",
            TableOptimizerConfiguration={"enabled": False, "roleArn": role_arn},
        )
        raise AssertionError("create_table_optimizer for a nonexistent table unexpectedly succeeded")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message", "")
        assert code == "EntityNotFoundException", (
            f"expected EntityNotFoundException, got {code!r}: {message!r}"
        )
        assert message == _filled(_ENTITY_NOT_FOUND, message), f"unexpected not-found message {message!r}"

    # Effect absent: no dangling optimizer was persisted for the nonexistent table.
    absence_code, absence_message = _error_code(
        lambda: glue.get_table_optimizer(
            CatalogId=account_id,
            DatabaseName=db_name,
            TableName=missing_table,
            Type="compaction",
        )
    )
    assert absence_code == "EntityNotFoundException", (
        f"expected get_table_optimizer on a never-created table to report EntityNotFoundException "
        f"(no dangling optimizer persisted), got {absence_code!r}"
    )
    assert absence_message == _filled(_ENTITY_NOT_FOUND, absence_message), absence_message


_GLUE_SERVICE_ROLE_POLICY = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"


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


def _error_code(fn: Any) -> tuple[str, str]:
    """Return (code, message) of the ClientError fn() raises; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _safe_delete_database(glue: Any, db_name: str) -> None:
    try:
        glue.delete_database(Name=db_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _safe_delete_table(glue: Any, db_name: str, table_name: str) -> None:
    try:
        glue.delete_table(DatabaseName=db_name, Name=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


