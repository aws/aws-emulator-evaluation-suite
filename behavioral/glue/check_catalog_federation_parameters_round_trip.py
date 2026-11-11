"""catalog-federation-parameters-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "catalog-federation-parameters-round-trip"
GROUP = "representation"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCatalog rejects a plain native catalog and a FederatedCatalog on an unregistered data
    source, and GetCatalog shows neither attempt persisted; a FederatedCatalog on an S3 Tables
    bucket succeeds as a positive control.
    """
    glue = ctx.client("glue")
    s3tables = ctx.client("s3tables")

    bucket_name = ctx.unique_name("sim2real-behav-fedctl-").lower().replace("_", "-")
    bucket_arn = s3tables.create_table_bucket(name=bucket_name, tags={"sim2real": CHECK})["arn"]
    ctx.on_cleanup(lambda: _delete_table_bucket_ignore_missing(s3tables, bucket_arn))

    # Positive control: CreateCatalog is not blanket-denied, so the refusals below are specific.
    control_name = ctx.unique_name("sim2real-behav-fedctl-cat-").lower().replace("_", "-")
    glue.create_catalog(
        Name=control_name,
        CatalogInput={"FederatedCatalog": {"ConnectionName": "aws:s3tables", "Identifier": bucket_arn}},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_catalog_ignore_missing(glue, control_name))

    control = glue.get_catalog(CatalogId=control_name)["Catalog"]
    assert control["Name"] == control_name, f"expected positive-control catalog Name={control_name!r}, got {control['Name']!r}"

    catalog_name = ctx.unique_name("sim2real-behav-cat-").lower().replace("_", "-")
    params = {
        "federation.source.host": "example-cluster.abc123.us-west-2.redshift.amazonaws.com",
        "federation.source.port": "5439",
    }

    # Plain (non-federated) CreateCatalog is rejected outright.
    code_native, message_native = _error(
        lambda: glue.create_catalog(Name=catalog_name, CatalogInput={"Parameters": params})
    )
    assert code_native == "InvalidInputException", f"expected InvalidInputException, got {code_native!r}"
    expected_native = "Create glue native catalog is not supported."
    assert message_native == expected_native, (
        f"expected CreateCatalog's native-catalog refusal message {expected_native!r}, got {message_native!r}"
    )

    # A FederatedCatalog pointing at a connection to an unregistered data source is
    # denied, not silently accepted with a partial/degraded catalog.
    conn_name = ctx.unique_name("sim2real-behav-catconn-").lower().replace("_", "-")
    glue.create_connection(
        ConnectionInput={
            "Name": conn_name,
            "ConnectionType": "JDBC",
            "ConnectionProperties": {
                "JDBC_CONNECTION_URL": "jdbc:redshift://placeholder.example.com:5439/dev",
                "USERNAME": "placeholder_user",
                "PASSWORD": "placeholder_pw",
            },
        },
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_connection(ConnectionName=conn_name))

    code_fed, message_fed = _error(
        lambda: glue.create_catalog(
            Name=catalog_name,
            CatalogInput={
                "FederatedCatalog": {
                    "ConnectionName": conn_name,
                    "ConnectionType": "REDSHIFT",
                    "Identifier": catalog_name,
                },
                "Parameters": params,
                "CreateDatabaseDefaultPermissions": [],
                "CreateTableDefaultPermissions": [],
            },
        )
    )
    assert code_fed == "AccessDeniedException", f"expected AccessDeniedException, got {code_fed!r}"
    expected_fed = f"The data source [{catalog_name}] is not registered."
    assert message_fed == expected_fed, (
        f"expected CreateCatalog's unregistered-data-source message {expected_fed!r}, got {message_fed!r}"
    )

    # Effect absent: no catalog -- with these Parameters or otherwise -- was ever
    # created under this name by either rejected attempt.
    get_code, get_message = _error(lambda: glue.get_catalog(CatalogId=catalog_name))
    assert get_code == "EntityNotFoundException", f"expected EntityNotFoundException, got {get_code!r}"
    expected_get = "Catalog not found."
    assert get_message == expected_get, (
        f"expected GetCatalog's not-found message {expected_get!r}, got {get_message!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return the AWS error (Code, Message) it raised. An unexpected success
    raises, so accepting what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_catalog_ignore_missing(glue, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        glue.delete_catalog(CatalogId=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _delete_table_bucket_ignore_missing(s3tables, bucket_arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        s3tables.delete_table_bucket(tableBucketARN=bucket_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("NotFoundException", "NoSuchTableBucket"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

