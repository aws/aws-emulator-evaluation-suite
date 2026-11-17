"""catalog-update-rejects-federated-catalog-and-unknown-id."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "catalog-update-rejects-federated-catalog-and-unknown-id"
GROUP = "state-machine"
SERVICES = ["glue", "s3tables"]


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _error_code(fn) -> str:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateCatalog rejects changing a federated catalog's own CatalogInput, leaving it
    untouched, and rejects an unknown catalog id with a different, lookup-specific error.
    """
    glue = ctx.client("glue")
    s3tables = ctx.client("s3tables")

    bucket_name = ctx.unique_name("sim2real-behav-catimp-").lower().replace("_", "-")
    bucket_arn = s3tables.create_table_bucket(name=bucket_name, tags={"sim2real": CHECK})["arn"]
    ctx.on_cleanup(_teardown(lambda: s3tables.delete_table_bucket(tableBucketARN=bucket_arn), "NotFoundException"))

    catalog_id = ctx.unique_name("sim2real-behav-catalog-").replace("_", "-")
    glue.create_catalog(
        Name=catalog_id,
        CatalogInput={
            "Description": "original description",
            "FederatedCatalog": {"ConnectionName": "aws:s3tables", "Identifier": bucket_arn},
        },
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(_teardown(lambda: glue.delete_catalog(CatalogId=catalog_id), "EntityNotFoundException"))

    # negative: a federated catalog's own CatalogInput cannot be changed through UpdateCatalog
    code1, msg1 = _error(lambda: glue.update_catalog(
        CatalogId=catalog_id, CatalogInput={"Description": "rejected description"}
    ))
    assert code1 == "InvalidInputException", f"UpdateCatalog on a federated catalog gave {code1!r}"
    assert msg1 == "Update on FederateCatalog is not allowed.", f"unexpected message: {msg1!r}"

    # the effect is absent: the rejected update left the catalog's Description untouched
    unchanged = glue.get_catalog(CatalogId=catalog_id)["Catalog"]
    assert unchanged["Description"] == "original description", (
        f"a rejected UpdateCatalog changed Description anyway: {unchanged['Description']!r}"
    )

    # negative: updating a catalog id that was never created is rejected differently (lookup,
    # not the federated-catalog restriction)
    missing_catalog_id = ctx.unique_name("sim2real-behav-catalog-missing-")
    code2 = _error_code(lambda: glue.update_catalog(
        CatalogId=missing_catalog_id, CatalogInput={"Description": "x"}
    ))
    assert code2 == "EntityNotFoundException", f"UpdateCatalog on an unknown catalog gave {code2!r}"

    # delete proves gone: the catalog no longer answers Get or Update
    glue.delete_catalog(CatalogId=catalog_id)
    code_get = _error_code(lambda: glue.get_catalog(CatalogId=catalog_id))
    assert code_get == "EntityNotFoundException", f"reading a deleted catalog gave {code_get!r}"
    code_update = _error_code(lambda: glue.update_catalog(
        CatalogId=catalog_id, CatalogInput={"Description": "y"}
    ))
    assert code_update == "EntityNotFoundException", f"updating a deleted catalog gave {code_update!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
