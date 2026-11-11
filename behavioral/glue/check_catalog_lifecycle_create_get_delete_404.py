"""catalog-lifecycle-create-get-delete-404."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "catalog-lifecycle-create-get-delete-404"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCatalog returns a federated catalog's Name, Description and S3 Tables federation, and after
    DeleteCatalog both GetCatalog and a second DeleteCatalog fail with EntityNotFoundException 'Catalog not
    found.'.
    """
    glue = ctx.client("glue")
    s3tables = ctx.client("s3tables")

    bucket_name = ctx.unique_name("sim2real-s3tables-").lower().replace("_", "-")
    bucket_arn = s3tables.create_table_bucket(
        name=bucket_name, tags={"sim2real": "check-catalog-lifecycle"}
    )["arn"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: s3tables.delete_table_bucket(tableBucketARN=bucket_arn)))

    catalog_id = ctx.unique_name("sim2real-catalog-").replace("_", "-")
    description = "behavioral fidelity check catalog"

    glue.create_catalog(
        Name=catalog_id,
        CatalogInput={
            "Description": description,
            "FederatedCatalog": {
                "ConnectionName": "aws:s3tables",
                "Identifier": bucket_arn,
            },
        },
        Tags={"sim2real": "check-catalog-lifecycle"},
    )

    ctx.on_cleanup(lambda: _ignore_missing(lambda: glue.delete_catalog(CatalogId=catalog_id)))

    got = glue.get_catalog(CatalogId=catalog_id)["Catalog"]
    assert got["Name"] == catalog_id, f"expected Name={catalog_id!r}, got {got.get('Name')!r}"
    assert got["Description"] == description, (
        f"expected Description={description!r}, got {got.get('Description')!r}"
    )
    federated = got["FederatedCatalog"]
    assert federated["ConnectionName"] == "aws:s3tables", (
        f"expected ConnectionName='aws:s3tables', got {federated.get('ConnectionName')!r}"
    )
    assert federated["Identifier"] == bucket_arn, (
        f"expected Identifier={bucket_arn!r}, got {federated.get('Identifier')!r}"
    )

    glue.delete_catalog(CatalogId=catalog_id)

    code, message = _error(lambda: glue.get_catalog(CatalogId=catalog_id))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code!r}"
    assert message == "Catalog not found.", message

    second_delete_code, second_delete_message = _error(lambda: glue.delete_catalog(CatalogId=catalog_id))
    assert second_delete_code == "EntityNotFoundException", (
        f"expected second DeleteCatalog on dead id to raise EntityNotFoundException, got {second_delete_code!r}"
    )
    assert second_delete_message == "Catalog not found.", second_delete_message


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises: real AWS refuses it."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it succeeded and returned {result!r}")


def _ignore_missing(fn):
    """Best-effort teardown: the resource may already be gone."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("EntityNotFoundException", "NotFoundException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
