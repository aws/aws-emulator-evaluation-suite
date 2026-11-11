"""create-table-optimizer-nonexistent-table-rejected."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "create-table-optimizer-nonexistent-table-rejected"
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
_GET_INELIGIBLE = (
    "Request Validation Failed: Unsupported Table type (Service: glue; Status Code: 400; "
    "Error Code: InvalidInputException; Request ID: {rid}; Proxy: null)"
)


def _filled(template, message):
    """`template` with its {rid} slots filled, in order, from the request ids `message` carries:
    the per-call part each wrapped service appends."""
    rids = iter(re.findall(r"Request ID: ([0-9a-f-]+);", message or ""))
    return re.sub(r"\{rid\}", lambda m: next(rids, "?"), template)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Create- and GetTableOptimizer on a table that does not exist raise EntityNotFoundException,
    while on an existing non-Iceberg table they raise InvalidInputException, each with its exact
    message.
    """
    glue = ctx.client("glue")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account_id}:role/sim2real-glue-optimizer-role-placeholder"

    db_name = ctx.unique_name("sim2real-glue-db-")
    real_table_name = ctx.unique_name("sim2real-glue-tbl-")
    bogus_table_name = ctx.unique_name("sim2real-glue-missing-")

    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": real_table_name,
            "StorageDescriptor": {
                "Columns": [{"Name": "col1", "Type": "string"}],
                "Location": "s3://sim2real-glue-bucket-placeholder/data/",
            },
            "PartitionKeys": [],
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=real_table_name))

    config = {"roleArn": role_arn, "enabled": True}

    code, message = _error_code(
        lambda: glue.create_table_optimizer(
            CatalogId=account_id,
            DatabaseName=db_name,
            TableName=bogus_table_name,
            Type="compaction",
            TableOptimizerConfiguration=config,
        )
    )
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}"
    assert message == _filled(_ENTITY_NOT_FOUND, message), f"unexpected not-found message {message!r}"

    # Effect absent: no optimizer was created for the nonexistent table.
    code, message = _error_code(
        lambda: glue.get_table_optimizer(
            CatalogId=account_id,
            DatabaseName=db_name,
            TableName=bogus_table_name,
            Type="compaction",
        )
    )
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}"
    assert message == _filled(_ENTITY_NOT_FOUND, message), f"unexpected not-found message {message!r}"

    # Positive control: the real table is found, so the rejection reason is different
    # (not Iceberg/governed-format compatible) -- distinguishing "missing" from "ineligible".
    code, message = _error_code(
        lambda: glue.create_table_optimizer(
            CatalogId=account_id,
            DatabaseName=db_name,
            TableName=real_table_name,
            Type="compaction",
            TableOptimizerConfiguration=config,
        )
    )
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code}"
    assert message == _filled(_CREATE_INELIGIBLE, message), f"unexpected ineligible-table message {message!r}"

    # Terminal read: independent of the mutating call above -- GetTableOptimizer enforces the
    # same format ineligibility on the read path, so nothing is retrievable for this table either.
    code, message = _error_code(
        lambda: glue.get_table_optimizer(
            CatalogId=account_id,
            DatabaseName=db_name,
            TableName=real_table_name,
            Type="compaction",
        )
    )
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code}"
    assert message == _filled(_GET_INELIGIBLE, message), f"unexpected ineligible-table message {message!r}"


def _error_code(fn):
    """Return (code, message) of the ClientError fn() raises; raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
