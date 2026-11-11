"""get-unfiltered-partition-metadata-not-found-exact-code."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "get-unfiltered-partition-metadata-not-found-exact-code"
GROUP = "error-semantics"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:lakeformation-data-lake-settings")
def run(ctx) -> None:
    """GetUnfilteredPartitionMetadata denies a plain IAM caller (even a Data Lake admin with grants)
    with AccessDeniedException for both existing and missing partitions, never leaking not-found.
    Plain GetPartition is the control: it sees the partition and reports the missing one.
    """
    glue = ctx.client("glue")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    caller_arn = _normalize_principal_arn(ctx.client("sts").get_caller_identity()["Arn"])
    _ensure_data_lake_admin(ctx, caller_arn)

    db_name = ctx.unique_name("sim2real-glue-ufpm-db-")
    table_name = ctx.unique_name("sim2real-glue-ufpm-tbl-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    storage_descriptor = {
        "Columns": [{"Name": "value", "Type": "string"}],
        "Location": f"s3://{ctx.unique_name('sim2real-glue-ufpm-bkt-')}/data/",
    }
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "StorageDescriptor": storage_descriptor,
            "PartitionKeys": [{"Name": "dt", "Type": "string"}],
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=table_name))

    # Also grant table-level DESCRIBE/SELECT, so neither available remediation clears the denial.
    _grant_lf_permissions(ctx, caller_arn, db_name, table_name)

    existing_values = ["2024-01-01"]
    glue.create_partition(
        DatabaseName=db_name,
        TableName=table_name,
        PartitionInput={
            "Values": existing_values,
            "StorageDescriptor": {
                **storage_descriptor,
                "Location": storage_descriptor["Location"] + "dt=2024-01-01/",
            },
        },
    )
    ctx.on_cleanup(
        lambda: glue.delete_partition(
            DatabaseName=db_name, TableName=table_name, PartitionValues=existing_values
        )
    )

    got = glue.get_partition(
        DatabaseName=db_name, TableName=table_name, PartitionValues=existing_values
    )
    assert got["Partition"]["Values"] == existing_values, (
        f"expected {existing_values}, got {got['Partition']['Values']}"
    )

    # This API is meant for query engines using a vended session; a plain IAM caller is denied.
    code, message = _error(
        lambda: glue.get_unfiltered_partition_metadata(
            CatalogId=account_id,
            DatabaseName=db_name,
            TableName=table_name,
            PartitionValues=existing_values,
            SupportedPermissionTypes=["COLUMN_PERMISSION"],
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected = ""
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Authorization is checked before partition existence.
    missing_values = ["1999-12-31"]
    code, message = _error(
        lambda: glue.get_unfiltered_partition_metadata(
            CatalogId=account_id,
            DatabaseName=db_name,
            TableName=table_name,
            PartitionValues=missing_values,
            SupportedPermissionTypes=["COLUMN_PERMISSION"],
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected = ""
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code_after, message_after = _error(
        lambda: glue.get_partition(
            DatabaseName=db_name, TableName=table_name, PartitionValues=missing_values
        )
    )
    assert code_after == "EntityNotFoundException", (
        f"expected EntityNotFoundException, got {code_after}"
    )
    expected = "Cannot find partition."
    assert message_after == expected, f"expected message {expected!r}, got {message_after!r}"


def _error(fn: Any) -> tuple[str, str]:
    """Call fn() and return the (code, message) of the ClientError it raises; success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _ensure_data_lake_admin(ctx, principal_arn: str) -> None:
    """Add the caller as a Lake Formation Data Lake Administrator. DataLakeAdmins is an
    account-global singleton, so the current list is restored exactly on cleanup."""
    lf = ctx.client("lakeformation")
    current = lf.get_data_lake_settings()["DataLakeSettings"]
    admins = current.get("DataLakeAdmins", [])
    if any(a.get("DataLakePrincipalIdentifier") == principal_arn for a in admins):
        return

    original_admins = list(admins)

    def _restore() -> None:
        restored = dict(current)
        restored["DataLakeAdmins"] = original_admins
        lf.put_data_lake_settings(DataLakeSettings=restored)

    ctx.on_cleanup(_restore)

    updated = dict(current)
    updated["DataLakeAdmins"] = original_admins + [
        {"DataLakePrincipalIdentifier": principal_arn}
    ]
    lf.put_data_lake_settings(DataLakeSettings=updated)


def _grant_lf_permissions(ctx, principal_arn: str, db_name: str, table_name: str) -> None:
    """Best-effort Lake Formation DESCRIBE/SELECT grant on the database/table; a rejected grant
    leaves the denial assertions valid."""
    from botocore.exceptions import ClientError

    lf = ctx.client("lakeformation")
    try:
        lf.grant_permissions(
            Principal={"DataLakePrincipalIdentifier": principal_arn},
            Resource={"Database": {"Name": db_name}},
            Permissions=["DESCRIBE"],
        )
        lf.grant_permissions(
            Principal={"DataLakePrincipalIdentifier": principal_arn},
            Resource={"Table": {"DatabaseName": db_name, "Name": table_name}},
            Permissions=["DESCRIBE", "SELECT"],
        )
    except ClientError:
        pass


def _normalize_principal_arn(arn: str) -> str:
    """Convert an STS assumed-role session ARN into its IAM role ARN, which Lake Formation's
    GrantPermissions requires."""
    if ":assumed-role/" not in arn:
        return arn
    _, _, account_and_role = arn.partition(":assumed-role/")
    prefix, _, _ = arn.partition(":assumed-role/")
    account_id = prefix.split(":")[4]
    role_name = account_and_role.split("/")[0]
    return f"arn:aws:iam::{account_id}:role/{role_name}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
