"""get-unfiltered-table-metadata-federation-retryable-error."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-unfiltered-table-metadata-federation-retryable-error"
GROUP = "error-semantics"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDatabase with a FederatedDatabase over a generic JDBC connection is rejected
    ("Federation not supported ...") and creates nothing, or, if accepted, reading table metadata
    from the unreachable source raises FederationSourceRetryableException."""
    glue = ctx.client("glue")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # Positive control: an ordinary (non-federated) database round-trips.
    control_db = ctx.unique_name("sim2real-glue-ufrm-ctrl-db-")
    glue.create_database(DatabaseInput={"Name": control_db}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=control_db))
    control = glue.get_database(Name=control_db)
    assert control["Database"]["Name"] == control_db, (
        f"expected the positive-control database {control_db!r} to round-trip through "
        f"GetDatabase, got {control['Database']['Name']!r}"
    )

    conn_name = _create_dead_jdbc_connection(ctx, host="192.0.2.1", port=5439)

    db_name = ctx.unique_name("sim2real-glue-ufrm-fed-db-")
    try:
        glue.create_database(
            DatabaseInput={
                "Name": db_name,
                "FederatedDatabase": {
                    "ConnectionName": conn_name,
                    "ConnectionType": "JDBC",
                    "Identifier": "sim2real-federation-probe",
                },
            },
            Tags={"sim2real": CHECK},
        )
    except ClientError as err:
        create_code, create_message = err.response["Error"]["Code"], err.response["Error"]["Message"]
    else:
        create_code = create_message = None

    if create_code is None:
        # CreateDatabase accepted the federated definition without eagerly contacting the
        # unreachable source; the federation contact (and its transient failure) happens on read.
        ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
        get_code = _error_code(
            lambda: glue.get_unfiltered_table_metadata(
                CatalogId=account_id,
                DatabaseName=db_name,
                Name="sim2real-probe-table",
                SupportedPermissionTypes=["COLUMN_PERMISSION"],
            )
        )
        assert get_code == "FederationSourceRetryableException", (
            f"expected FederationSourceRetryableException from GetUnfilteredTableMetadata "
            f"against an accepted-but-unreachable federated database, got {get_code!r}"
        )
    elif create_code == "FederationSourceRetryableException":
        # The federation source was validated eagerly at creation time.
        pass
    elif create_code == "InvalidInputException" and "federation" in (create_message or "").lower():
        # AWS rejects a generic ConnectionType="JDBC" federation source outright, distinct from a
        # malformed-request InvalidInputException, which would not name "federation".
        assert create_message == "Federation not supported for connection provided.", (
            f"expected the specific unsupported-connector message, got {create_message!r}"
        )
        list_names = {
            db["Name"]
            for page in glue.get_paginator("get_databases").paginate()
            for db in page["DatabaseList"]
        }
        assert db_name not in list_names, (
            f"CreateDatabase reported {create_code!r} yet {db_name!r} is visible in "
            "GetDatabases -- the rejection did not actually prevent creation"
        )
        get_after_code = _error_code(lambda: glue.get_database(Name=db_name))
        assert get_after_code == "EntityNotFoundException", (
            f"expected GetDatabase on the never-created {db_name!r} to fail with "
            f"EntityNotFoundException, got {get_after_code!r}"
        )
    else:
        raise AssertionError(
            "this account/region rejected the FederatedDatabase(ConnectionType='JDBC') "
            f"construction with CreateDatabase error {create_code!r} "
            f"(message={create_message!r}) instead of accepting it, failing with "
            "FederationSourceRetryableException, or failing with the known "
            "InvalidInputException/'Federation not supported' rejection"
        )


def _error_code(fn: Any) -> str:
    """Call fn(); return its Error.Code. A success fails the check."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    raise AssertionError(f"the call succeeded where a ClientError was expected: {result!r}")


def _create_dead_jdbc_connection(ctx, *, host: str, port: int) -> str:
    glue = ctx.client("glue")
    conn_name = ctx.unique_name("sim2real-glue-deadconn-")
    glue.create_connection(
        ConnectionInput={
            "Name": conn_name,
            "Description": "sim2real: deliberately unroutable JDBC target for federation-error checks",
            "ConnectionType": "JDBC",
            "ConnectionProperties": {
                "JDBC_CONNECTION_URL": f"jdbc:redshift://{host}:{port}/dev",
                "USERNAME": "sim2real",
                "PASSWORD": "sim2real-placeholder",
            },
        },
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_connection(ConnectionName=conn_name))
    return conn_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
