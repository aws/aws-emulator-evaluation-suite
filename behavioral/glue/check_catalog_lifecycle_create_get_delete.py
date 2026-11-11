"""catalog-lifecycle-create-get-delete."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "catalog-lifecycle-create-get-delete"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCatalog returns the Name, Description and S3 Tables federation of a created catalog, and after
    DeleteCatalog both GetCatalog and a second DeleteCatalog fail with EntityNotFoundException 'Catalog not
    found.'.
    """
    glue = ctx.client("glue")
    s3tables = ctx.client("s3tables")

    bucket_name = ctx.unique_name("sim2real-behav-cat-").lower().replace("_", "-")
    bucket_arn = s3tables.create_table_bucket(
        name=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav-cat"},
    )["arn"]
    ctx.on_cleanup(lambda: _delete_table_bucket_ignore_missing(s3tables, bucket_arn))

    name = ctx.unique_name("sim2real-behav-catalog-")
    description = "sim2real behavioral fidelity check catalog"

    glue.create_catalog(
        Name=name,
        CatalogInput={
            "Description": description,
            "FederatedCatalog": {"ConnectionName": "aws:s3tables", "Identifier": bucket_arn},
        },
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_catalog_ignore_missing(glue, name))

    got = glue.get_catalog(CatalogId=name)["Catalog"]
    assert got["Name"] == name, f"expected Name {name!r}, got {got['Name']!r}"
    assert got["Description"] == description, (
        f"expected Description {description!r}, got {got['Description']!r}"
    )
    assert got["FederatedCatalog"]["ConnectionName"] == "aws:s3tables", (
        f"expected ConnectionName 'aws:s3tables', got {got['FederatedCatalog']['ConnectionName']!r}"
    )
    assert got["FederatedCatalog"]["Identifier"] == bucket_arn, (
        f"expected Identifier {bucket_arn!r}, got {got['FederatedCatalog']['Identifier']!r}"
    )

    glue.delete_catalog(CatalogId=name)

    code, message = _error(lambda: glue.get_catalog(CatalogId=name))
    assert code == "EntityNotFoundException", (
        f"expected GetCatalog on a deleted catalog to raise EntityNotFoundException, got {code!r}"
    )
    assert message == "Catalog not found.", message

    redelete_code, redelete_message = _error(lambda: glue.delete_catalog(CatalogId=name))
    assert redelete_code == "EntityNotFoundException", (
        f"expected DeleteCatalog on the already-deleted catalog to raise EntityNotFoundException, "
        f"got {redelete_code!r}"
    )
    assert redelete_message == "Catalog not found.", redelete_message


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises: real AWS refuses it."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it succeeded and returned {result!r}")


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
