"""create-catalog-duplicate-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-catalog-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCatalog with a name already in use fails with AlreadyExistsException 'Catalog already exists.'
    and leaves the original catalog's Description unchanged.
    """
    glue = ctx.client("glue")
    s3tables = ctx.client("s3tables")

    bucket_name = ctx.unique_name("sim2real-glue-catdup-").lower().replace("_", "-")
    bucket_arn = s3tables.create_table_bucket(name=bucket_name)["arn"]
    ctx.on_cleanup(lambda: _delete_table_bucket_ignore_missing(s3tables, bucket_arn))

    name = ctx.unique_name("sim2real-glue-catalog-")
    glue.create_catalog(Name=name, CatalogInput=_federated_input(bucket_arn, "original description"))
    ctx.on_cleanup(lambda: _delete_catalog_ignore_missing(glue, name))

    # Positive control: the catalog was actually created with our description.
    original = glue.get_catalog(CatalogId=name)["Catalog"]
    assert original["Name"] == name, f"expected Name={name!r}, got {original.get('Name')!r}"
    assert original.get("Description") == "original description", (
        f"expected Description='original description', got {original.get('Description')!r}"
    )

    # Negative: re-creating with the same Name (different CatalogInput) must be rejected.
    code, message = _error(
        lambda: glue.create_catalog(
            Name=name, CatalogInput=_federated_input(bucket_arn, "attempted overwrite description")
        )
    )
    assert code == "AlreadyExistsException", f"expected AlreadyExistsException, got {code!r}"
    assert message == "Catalog already exists.", f"unexpected CreateCatalog message: {message!r}"

    # Effect absent: the original catalog's description was not overwritten.
    after = glue.get_catalog(CatalogId=name)["Catalog"]
    assert after.get("Description") == "original description", (
        f"expected Description unchanged at 'original description', got {after.get('Description')!r}"
    )


def _federated_input(bucket_arn: str, description: str) -> dict:
    return {
        "Description": description,
        "FederatedCatalog": {"ConnectionName": "aws:s3tables", "Identifier": bucket_arn},
    }


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, because an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_catalog_ignore_missing(glue, catalog_id: str) -> None:
    try:
        glue.delete_catalog(CatalogId=catalog_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _delete_table_bucket_ignore_missing(s3tables, bucket_arn: str) -> None:
    try:
        s3tables.delete_table_bucket(tableBucketARN=bucket_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("NotFoundException", "NoSuchTableBucket"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
