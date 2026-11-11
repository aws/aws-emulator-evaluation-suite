"""get-catalog-federation-source-error-propagated."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "get-catalog-federation-source-error-propagated"
GROUP = "error-semantics"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCatalog with a FederatedCatalog naming an unregistered data source is rejected with
    AccessDeniedException ("... is not registered.") and creates nothing, while GetCatalog on the
    account root catalog succeeds as the positive control."""
    glue = ctx.client("glue")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # Positive control: ordinary Glue catalog reads succeed, so the rejection below is a
    # specific business decision, not a broadly-denied account/credential.
    root = glue.get_catalog(CatalogId=account_id)["Catalog"]
    assert root["CatalogId"] == account_id or root.get("Name") == account_id, root

    conn_name = _create_dead_jdbc_connection(
        ctx, host=f"{ctx.unique_name('sim2real-nx-')}.invalid", port=5439
    )

    catalog_name = ctx.unique_name("sim2real-glue-fedcat-").lower()
    create_code, create_message = _error_code_and_message(
        lambda: glue.create_catalog(
            Name=catalog_name,
            CatalogInput={
                "FederatedCatalog": {
                    "ConnectionName": conn_name,
                    "ConnectionType": "JDBC",
                    "Identifier": "sim2real-federation-probe",
                },
                "CreateDatabaseDefaultPermissions": [],
                "CreateTableDefaultPermissions": [],
            },
        )
    )
    assert create_code == "AccessDeniedException", (
        f"expected AccessDeniedException for an unregistered federation Identifier, "
        f"got {create_code!r} ({create_message!r})"
    )
    expected = 'The data source [sim2real-federation-probe] is not registered.'
    assert create_message == expected, (
        f"expected the not-registered message {expected!r}, distinguishing this from a generic "
        f"permission denial, got {create_message!r}"
    )

    # Effect absent: the rejected CreateCatalog did not actually create a catalog under this
    # name -- read via GetCatalog, an operation independent of the mutating CreateCatalog call.
    get_code, get_message = _error_code_and_message(lambda: glue.get_catalog(CatalogId=catalog_name))
    assert get_code == "EntityNotFoundException", get_code
    expected = 'Catalog not found.'
    assert get_message == expected, f"expected message {expected!r}, got {get_message!r}"


def _error_code_and_message(fn: Any) -> tuple[str, str]:
    """Call fn(); return (code, message) of its ClientError. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError rejection, but the call SUCCEEDED: {result!r}")


def _create_dead_jdbc_connection(ctx, *, host: str, port: int) -> str:
    glue = ctx.client("glue")
    conn_name = ctx.unique_name("sim2real-glue-deadconn-")
    glue.create_connection(
        ConnectionInput={
            "Name": conn_name,
            "Description": "sim2real: deliberately unreachable JDBC target for federation-error checks",
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
