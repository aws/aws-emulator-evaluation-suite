"""delete-catalog-nonexistent-not-found-exact-code."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-catalog-nonexistent-not-found-exact-code"
GROUP = "error-semantics"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCatalog on a deleted catalog and on a never-created id, and GetCatalog on the deleted
    one, raise EntityNotFoundException ("Catalog not found."); the federated S3 Tables catalog
    deletes first.
    """
    glue = ctx.client("glue")
    s3tables = ctx.client("s3tables")

    bucket_name = ctx.unique_name("sim2real-glue-catbkt-").lower().replace("_", "-")
    bucket_arn = s3tables.create_table_bucket(name=bucket_name, tags={"sim2real": CHECK})["arn"]
    ctx.on_cleanup(lambda: _delete_ignore_errors(lambda: s3tables.delete_table_bucket(tableBucketARN=bucket_arn)))

    catalog_name = ctx.unique_name("sim2real-glue-cat-").lower()
    glue.create_catalog(
        Name=catalog_name,
        CatalogInput={"FederatedCatalog": {"ConnectionName": "aws:s3tables", "Identifier": bucket_arn}},
        Tags={"sim2real": CHECK},
    )

    def _cleanup() -> None:
        from botocore.exceptions import ClientError

        try:
            glue.delete_catalog(CatalogId=catalog_name)
        except ClientError as err:
            # Already deleted by the check body itself; ignore not-found.
            if err.response["Error"]["Code"] != "EntityNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    # Positive control: deleting the real, existing catalog succeeds.
    glue.delete_catalog(CatalogId=catalog_name)

    # Negative 1: deleting the same id again, now that it really existed and was deleted.
    code, message = _error(lambda: glue.delete_catalog(CatalogId=catalog_name))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code!r}"
    assert message == "Catalog not found.", f"unexpected not-found message {message!r}"

    # Negative 2: deleting an id that was never created at all fails with the identical code.
    never_created = ctx.unique_name("sim2real-glue-nx-cat-").lower()
    never_code, never_message = _error(lambda: glue.delete_catalog(CatalogId=never_created))
    assert never_code == "EntityNotFoundException", f"expected EntityNotFoundException, got {never_code!r}"
    assert never_message == "Catalog not found.", f"unexpected not-found message {never_message!r}"

    # Effect absent: the catalog did not spring back into existence.
    get_code, get_message = _error(lambda: glue.get_catalog(CatalogId=catalog_name))
    assert get_code == "EntityNotFoundException", f"expected EntityNotFoundException, got {get_code!r}"
    assert get_message == "Catalog not found.", f"unexpected not-found message {get_message!r}"


def _error(fn: Any) -> tuple[str, str]:
    """Return (code, message) of the ClientError fn() raises; raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _delete_ignore_errors(fn: Any) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
